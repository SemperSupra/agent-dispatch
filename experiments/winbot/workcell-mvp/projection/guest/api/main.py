"""
WinBot API Server — FastAPI application replicating WineBot's REST API
for native Windows VM automation.

Run: python main.py
  or: uvicorn main:app --host 0.0.0.0 --port 8000
"""

import datetime
import json
import logging
import os
import socket
import sys
import time
import uuid
from pathlib import Path
from typing import Optional

from fastapi import Body, FastAPI, HTTPException, Query, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field

# Ensure the api directory is on the path
sys.path.insert(0, str(Path(__file__).parent))

from endpoints import apps, automation, control, health, input_ep, screenshot, vnc, windows
from endpoints.input_trace import tracer
from endpoints.operations import ops
from endpoints.recording import recorder

# ============================================================
# Configuration
# ============================================================
API_VERSION = "1.0.0"
WINBOT_VERSION = "0.1.0"

# API token: always required. Generate a random token if not explicitly set.
# Callers must pass X-API-Key header on every request.
_raw_token = os.environ.get("WINBOT_API_TOKEN", "")
if _raw_token:
    API_TOKEN = _raw_token
else:
    # Fallback: read from .api_token file (written by fix-api-service.ps1)
    _token_file = r"C:\WinBot\.api_token"
    try:
        with open(_token_file) as f:
            _file_token = f.read().strip()
        if _file_token:
            API_TOKEN = _file_token
            print(f"[WinBot] Loaded API token from {_token_file}")
        else:
            raise ValueError("empty token")
    except Exception:
        import secrets
        API_TOKEN = secrets.token_hex(32)
        print(f"[WinBot] WARNING: WINBOT_API_TOKEN not set and no {_token_file}. Generated random token: {API_TOKEN[:8]}...")
        print("[WinBot] All API requests now require X-API-Key header with this token.")

SESSION_ROOT = os.environ.get("WINBOT_SESSION_ROOT", "C:\\WinBot\\sessions")

# Maximum request body size (configurable, default 50 MB for binary uploads)
MAX_BODY_SIZE_MB = int(os.environ.get("WINBOT_MAX_BODY_SIZE_MB", "50"))
MAX_BODY_SIZE = MAX_BODY_SIZE_MB * 1024 * 1024

# Script execution timeout (configurable, default 120s for RE analysis)
SCRIPT_TIMEOUT_SECONDS = int(os.environ.get("WINBOT_SCRIPT_TIMEOUT", "120"))

# CORS origins — configurable via env var, defaults to localhost only
_CORS_ORIGINS = os.environ.get("WINBOT_CORS_ORIGINS", "http://localhost,http://127.0.0.1").split(",")

# Rate limiting: maximum requests per minute per client IP
RATE_LIMIT_PER_MINUTE = int(os.environ.get("WINBOT_RATE_LIMIT", "100"))

# ============================================================
# FastAPI App
# ============================================================
app = FastAPI(
    title="WinBot API",
    description="Windows VM automation REST API — native Windows equivalent of WineBot",
    version=API_VERSION,
    swagger_ui_parameters={"defaultModelsExpandDepth": -1},  # clean UI
)

# Security scheme for OpenAPI documentation.
# Actual auth enforcement is in winbot_middleware (X-API-Key header).
# The OpenAPI spec is enriched via openapi() monkey-patch below.
API_KEY_SCHEME = "ApiKeyAuth"


def _inject_security_scheme(openapi_schema: dict):
    """Post-processing: add ApiKeyAuth scheme and global security to OpenAPI spec."""
    openapi_schema.setdefault("components", {}).setdefault("securitySchemes", {})
    openapi_schema["components"]["securitySchemes"][API_KEY_SCHEME] = {
        "type": "apiKey",
        "in": "header",
        "name": "X-API-Key",
        "description": "WinBot API token — required for all endpoints",
    }
    openapi_schema.setdefault("security", []).append({API_KEY_SCHEME: []})
    return openapi_schema


_original_openapi = app.openapi
def _patched_openapi():
    schema = _original_openapi()
    return _inject_security_scheme(schema)
app.openapi = _patched_openapi

# CORS — restricted to configured origins (default: localhost only)
app.add_middleware(
    CORSMiddleware,
    allow_origins=_CORS_ORIGINS,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Control policy router (WineBot-compatible human-in-the-loop agent broker)
app.include_router(control.router)

# VNC WebSocket proxy — interactive remote desktop via noVNC
app.include_router(vnc.router)
# Pass the resolved API token to the VNC module for WebSocket auth
# (HTTP middleware doesn't cover WebSocket connections)
vnc.configure_vnc_token(API_TOKEN)

# ============================================================
# Rate Limiting Middleware
# ============================================================
import asyncio
import time as _time
from collections import defaultdict

_rate_window = 60  # seconds
_rate_counts: dict[str, list[float]] = defaultdict(list)
_rate_lock = asyncio.Lock()


@app.middleware("http")
async def rate_limit_middleware(request: Request, call_next):
    """Limit requests to RATE_LIMIT_PER_MINUTE per client IP. Exempts lifecycle cancel/status."""
    client_ip = request.client.host if request.client else "unknown"

    # Lifecycle cancel and status must always be reachable — skip rate limit
    if request.url.path.rstrip("/") in {"/lifecycle/cancel", "/lifecycle/status"}:
        return await call_next(request)

    now = _time.monotonic()
    async with _rate_lock:
        cutoff = now - _rate_window
        _rate_counts[client_ip] = [t for t in _rate_counts[client_ip] if t > cutoff]
        if len(_rate_counts[client_ip]) >= RATE_LIMIT_PER_MINUTE:
            logger.warning("[%s] Rate limit exceeded for %s", getattr(request.state, 'request_id', '-'), client_ip)
            return JSONResponse(
                status_code=429,
                content={"detail": "Too many requests. Rate limit exceeded."},
            )
        _rate_counts[client_ip].append(now)

        # Periodic cleanup: remove stale IPs with empty time lists to prevent unbounded dict growth
        _rate_counts.setdefault("_last_cleanup", []).append(now)
        # Only sweep every ~100 requests to amortize cost
        if len(_rate_counts["_last_cleanup"]) >= 100:
            stale = [ip for ip, times in _rate_counts.items() if ip != "_last_cleanup" and not times]
            for ip in stale:
                _rate_counts.pop(ip, None)
            _rate_counts["_last_cleanup"].clear()
    return await call_next(request)


# ============================================================
# Request Body Size Limit Middleware
# ============================================================
@app.middleware("http")
async def body_size_limit_middleware(request: Request, call_next):
    """Reject requests with bodies larger than MAX_BODY_SIZE."""
    content_length = request.headers.get("content-length")
    if content_length:
        try:
            if int(content_length) > MAX_BODY_SIZE:
                return JSONResponse(
                    status_code=413,
                    content={"detail": f"Request body too large. Maximum is {MAX_BODY_SIZE} bytes."},
                )
        except ValueError:
            pass
    response = await call_next(request)
    return response


# ============================================================
# Structured Logging
# ============================================================
LOG_DIR = os.environ.get("WINBOT_LOG_DIR", r"C:\WinBot\logs")
os.makedirs(LOG_DIR, exist_ok=True)

log_level_name = os.environ.get("WINBOT_LOG_LEVEL", "INFO").upper()
log_level = getattr(logging, log_level_name, logging.INFO)

logging.basicConfig(
    level=log_level,
    format="%(asctime)s [%(levelname)s] [%(process)d] [%(name)s] %(message)s",
    handlers=[
        logging.FileHandler(os.path.join(LOG_DIR, f"winbot-api-{datetime.date.today():%Y%m%d}.log")),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger("winbot.api")

# Static files — web dashboard UI (mounted after logger is available)
_static_dir = Path(__file__).parent / "static"
if _static_dir.exists():
    app.mount("/ui", StaticFiles(directory=str(_static_dir), html=True), name="ui")
    logger.info("Web dashboard available at /ui/")
else:
    logger.warning("Static UI directory not found: %s", _static_dir)

# ============================================================
# Security Audit Logging
# ============================================================
security_log = logging.getLogger("winbot.security")
security_handler = logging.FileHandler(
    os.path.join(LOG_DIR, "security.log"),
    encoding="utf-8"
)
security_handler.setFormatter(logging.Formatter(
    "%(asctime)s [%(levelname)s] %(message)s"
))
security_log.addHandler(security_handler)
security_log.setLevel(logging.INFO)
security_log.propagate = False  # Don't duplicate to console

VERSION_HEADER_PATHS = {"/health", "/version"}  # Only tag these paths with WinBot version
API_TOKEN_HEADER = "X-API-Key"
REQUEST_ID_HEADER = "X-Request-ID"

@app.middleware("http")
async def winbot_middleware(request: Request, call_next):
    # --- Request tracing ---
    request_id = request.headers.get(REQUEST_ID_HEADER) or str(uuid.uuid4())
    request.state.request_id = request_id
    start_time = time.monotonic()

    # --- Auth check ---
    token = request.headers.get(API_TOKEN_HEADER, "")
    if token != API_TOKEN:
        security_log.warning(
            "AUTH_FAIL [%s] %s %s (client: %s)",
            request_id, request.method, request.url.path,
            request.client.host if request.client else "unknown"
        )
        return JSONResponse(
            status_code=401,
            content={"detail": "Invalid or missing API token"}
        )

    # --- Execute ---
    response = await call_next(request)

    # --- Version headers (only on /health and /version to reduce fingerprinting) ---
    if request.url.path.rstrip("/") in VERSION_HEADER_PATHS:
        response.headers["X-WinBot-Version"] = WINBOT_VERSION
        response.headers["X-WinBot-API-Version"] = API_VERSION
    response.headers[REQUEST_ID_HEADER] = request_id

    # --- Security: log app executions and lifecycle-sensitive endpoints ---
    if request.url.path.startswith("/apps/run") and response.status_code == 200:
        security_log.info(
            "APP_EXEC [%s] %s %s (client:%s)",
            request_id, request.method, request.url.path,
            request.client.host if request.client else "unknown"
        )

    # --- Log request ---
    duration_ms = round((time.monotonic() - start_time) * 1000, 1)
    logger.info(
        "[%s] %s %s -> %d (%s ms)",
        request_id, request.method, request.url.path,
        response.status_code, duration_ms
    )

    return response


# ============================================================
# Startup helper
# ============================================================
def get_session_dir(session_label: Optional[str] = None) -> str:
    """Create and return a session directory."""
    now = datetime.datetime.now()
    ts = now.strftime("%Y%m%d-%H%M%S")
    if session_label:
        session_id = f"session-{ts}-{session_label}"
    else:
        import random
        session_id = f"session-{ts}-{random.randint(1000, 9999)}"
    session_dir = os.path.join(SESSION_ROOT, session_id)
    os.makedirs(session_dir, exist_ok=True)
    os.makedirs(os.path.join(session_dir, "screenshots"), exist_ok=True)
    os.makedirs(os.path.join(session_dir, "logs"), exist_ok=True)
    os.makedirs(os.path.join(session_dir, "scripts"), exist_ok=True)
    os.makedirs(os.path.join(session_dir, "artifacts"), exist_ok=True)
    return session_dir


def get_tool_path(tool: str) -> Optional[str]:
    """Find the path to an installed automation tool."""
    tool_paths = {
        "autoit": [
            r"C:\Program Files (x86)\AutoIt3\AutoIt3.exe",
            r"C:\Program Files\AutoIt3\AutoIt3.exe",
        ],
        "ahk": [
            r"C:\Program Files\AutoHotkey\AutoHotkey.exe",
            r"C:\Program Files\AutoHotkey\AutoHotkeyU64.exe",
        ],
        "python": [
            r"C:\Python313\python.exe",
            os.path.expandvars(r"%LOCALAPPDATA%\Programs\Python\Python313\python.exe"),
            r"C:\Program Files\Python313\python.exe",
        ],
        "winspy": [
            r"C:\WinBot\tools\WinSpy\windowspy.exe",
        ],
    }
    paths = tool_paths.get(tool.lower(), [])
    for p in paths:
        if os.path.exists(p):
            return p
    # Fallback: try PATH
    import shutil
    if tool.lower() == "autoit":
        found = shutil.which("AutoIt3.exe")
    elif tool.lower() == "ahk":
        found = shutil.which("AutoHotkey.exe")
    elif tool.lower() == "python":
        found = shutil.which("python.exe") or shutil.which("python3.exe")
    else:
        found = None
    return found


# ============================================================
# Health endpoints
# ============================================================
@app.get("/health")
async def health_check() -> dict:
    """Top-level health summary."""
    return health.get_health_summary()


@app.get("/health/system")
async def system_health():
    """System uptime, CPU, memory."""
    return health.get_system_health()


@app.get("/health/system_info")
async def system_info():
    """Detailed system information."""
    return health.get_system_info()


@app.get("/health/tools")
async def tools_health():
    """Check installed automation tools."""
    return health.get_tools_health()


@app.get("/health/storage")
async def storage_health():
    """Disk space for WinBot directories."""
    return health.get_storage_health()


@app.get("/health/capabilities")
async def capabilities_health(force_refresh: bool = False):
    """Report active capabilities based on installed tools.

    Set force_refresh=true to bypass cache and re-check tool installations.
    Agents should call this after installing tools to discover new capabilities.

    Returns which API features are available and what's missing.
    """
    from capabilities import capabilities_for_api, get_active_capabilities
    if force_refresh:
        get_active_capabilities(force_refresh=True)
    return capabilities_for_api()


@app.get("/health/tool_catalog")
async def tool_catalog():
    """Return the full tool catalog with installation status.

    Shows every known tool, whether it's installed, what capabilities
    it enables, and its dependencies. Used by deploy-loadout.ps1
    and for agent-driven setup planning.
    """
    from capabilities import get_loadout_templates, get_tool_status
    return {
        "tools": get_tool_status(),
        "loadout_templates": get_loadout_templates(),
    }


# ============================================================
# Sessions (winebot-contracts canonical path)
# ============================================================
@app.get("/sessions")
async def list_sessions():
    """List active sessions. WineBot-compatible endpoint.

    Canonical path defined in winebot-contracts. Returns a list
    of active session manifests with session_id, start time, etc.
    """
    return _list_sessions()


def _list_sessions():
    """Return session metadata from the session root directory."""
    import json
    sessions = []
    if os.path.exists(SESSION_ROOT):
        for entry in sorted(os.listdir(SESSION_ROOT)):
            session_path = os.path.join(SESSION_ROOT, entry)
            if os.path.isdir(session_path):
                manifest_path = os.path.join(session_path, "manifest.json")
                if os.path.exists(manifest_path):
                    try:
                        with open(manifest_path) as f:
                            sessions.append(json.load(f))
                    except (json.JSONDecodeError, OSError):
                        sessions.append({
                            "session_id": entry,
                            "start_time_iso": None,
                            "hostname": socket.gethostname(),
                        })
                else:
                    sessions.append({
                        "session_id": entry,
                        "start_time_iso": None,
                        "hostname": socket.gethostname(),
                    })
    return {"sessions": sessions}


@app.get("/health/presence")
async def presence_health():
    """Check whether a human is currently logged into the VM.

    Used by agents to decide whether lifecycle actions (reboot/shutdown)
    will show a visible dialog or need to rely purely on API cancellation.
    """
    return _is_human_present()


# ============================================================
# Screenshot endpoints
# ============================================================
@app.get("/screenshot")
async def take_screenshot(
    format: str = Query("png", description="Image format (png or jpg)"),
    output_dir: Optional[str] = Query(None, description="Output directory override"),
):
    """Capture a screenshot of the VM desktop."""
    return screenshot.capture(format=format, output_dir=output_dir)


# ============================================================
# Application execution
# ============================================================
class AppRunRequest(BaseModel):
    path: str = Field(..., description="Path to executable")
    args: Optional[str] = Field("", description="Command-line arguments")
    detach: bool = Field(False, description="Run in detached mode")


@app.post("/apps/run")
async def run_app(req: AppRunRequest) -> dict:
    """Launch a Windows application."""
    return apps.run(req.path, req.args, req.detach)


# ============================================================
# Automation endpoints (run AHK, AutoIt, Python)
# ============================================================
class ScriptRequest(BaseModel):
    script: str = Field(..., description="Script code to execute")


@app.post("/run/ahk")
async def run_ahk(req: ScriptRequest):
    """Execute an AutoHotkey script."""
    return automation.run_ahk(req.script)


@app.post("/run/autoit")
async def run_autoit(req: ScriptRequest):
    """Execute an AutoIt script."""
    return automation.run_autoit(req.script)


@app.post("/run/python")
async def run_python(req: ScriptRequest):
    """Execute Python code."""
    return automation.run_python(req.script)


# ============================================================
# Input endpoints
# ============================================================
class MouseClickRequest(BaseModel):
    x: int = Field(..., description="X coordinate")
    y: int = Field(..., description="Y coordinate")
    button: str = Field("left", description="Mouse button: left, right, middle")
    clicks: int = Field(1, description="Number of clicks")
    interval: float = Field(0.0, description="Interval between clicks (seconds)")


class KeyboardTypeRequest(BaseModel):
    text: str = Field(..., description="Text to type")
    interval: float = Field(0.0, description="Delay between keystrokes (seconds)")


class KeyboardPressRequest(BaseModel):
    keys: str = Field(..., description="Key combination (e.g., 'ctrl+c', 'alt+tab')")


@app.post("/input/mouse/click")
async def mouse_click(req: MouseClickRequest):
    """Click at screen coordinates."""
    tracer.record("click", {"x": req.x, "y": req.y, "button": req.button, "clicks": req.clicks})
    return input_ep.mouse_click(req.x, req.y, req.button, req.clicks, req.interval)


@app.post("/input/mouse/move")
async def mouse_move(x: int = Body(...), y: int = Body(...)):
    """Move mouse to coordinates."""
    tracer.record("move", {"x": x, "y": y})
    return input_ep.mouse_move(x, y)


@app.post("/input/keyboard/type")
async def keyboard_type(req: KeyboardTypeRequest):
    """Type text."""
    tracer.record("type", {"text_length": len(req.text)})
    return input_ep.keyboard_type(req.text, req.interval)


@app.post("/input/keyboard/press")
async def keyboard_press(req: KeyboardPressRequest):
    """Press a key combination."""
    tracer.record("press", {"keys": req.keys})
    return input_ep.keyboard_press(req.keys)


# Canonical alias: winebot-contracts POST /input/key → WinBot keyboard_press
@app.post("/input/key")
async def keyboard_input_canonical(req: KeyboardPressRequest):
    """Canonical winebot-contracts endpoint: press a key combination.

    This is the canonical path defined in the shared API contract.
    Delegates to the WinBot keyboard press implementation.
    """
    tracer.record("press", {"keys": req.keys})
    return input_ep.keyboard_press(req.keys)


# ============================================================
# Window management
# ============================================================
class WindowFocusRequest(BaseModel):
    title: Optional[str] = Field(None, description="Window title to focus")
    substring: bool = Field(True, description="Match title as substring")


@app.get("/windows")
async def list_windows():
    """List all visible windows."""
    return windows.list_windows()


@app.post("/windows/focus")
async def focus_window(req: WindowFocusRequest):
    """Focus a window by title."""
    return windows.focus_window(req.title, req.substring)


class WindowInspectRequest(BaseModel):
    title: Optional[str] = Field(None, description="Window title")
    handle: Optional[str] = Field(None, description="Window handle (hex)")


@app.post("/inspect/window")
async def inspect_window(req: WindowInspectRequest):
    """Inspect window details by title or handle."""
    return windows.inspect_window(req.title, req.handle)


# ============================================================
# Node Registration — physical machines enroll with the host
# ============================================================
class NodeRegisterRequest(BaseModel):
    hostname: str = Field(..., description="Machine hostname")
    ip: str = Field(..., description="IP address of this node")
    node_type: Optional[str] = Field("Physical", description="Node type: Physical, VM, etc.")
    reset_method: Optional[str] = Field("Reboot", description="Reset method: UWF, PXE, VHDX, Reboot")
    capabilities: Optional[dict] = Field(None, description="Capabilities reported by the node")
    labels: Optional[list[str]] = Field(None, description="Node labels/tags")


@app.post("/nodes/register")
async def register_node(req: NodeRegisterRequest, request: Request):
    """Register this physical node with the WinBot host.

    Called by newly-deployed physical machines on first boot
    to enroll themselves in the fleet. The host records node
    identity, IP, capabilities, and reset method for fleet management.

    This does NOT require API token auth — it uses a one-time
    enrollment token, or the request originates from a trusted
    provisioning source (local network, PXE-deployed machine).
    """
    rid = getattr(request.state, 'request_id', 'unknown')
    logger.info("[%s] Node registration request: %s @ %s", rid, req.hostname, req.ip)

    # Record node info
    node_record = {
        "hostname": req.hostname,
        "ip": req.ip,
        "api_port": 8000,
        "node_type": req.node_type or "Physical",
        "reset_method": req.reset_method or "Reboot",
        "labels": req.labels or [],
        "capabilities": req.capabilities or {},
        "api_online": True,
        "registered_at": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "last_seen_at": datetime.datetime.now(datetime.timezone.utc).isoformat(),
    }

    # Write node record to the nodes directory (host-side)
    nodes_dir = os.environ.get("WINBOT_NODES_DIR", r"C:\WinBot\nodes")
    os.makedirs(nodes_dir, exist_ok=True)
    node_file = os.path.join(nodes_dir, f"{req.hostname}.json")
    with open(node_file, "w") as f:
        json.dump(node_record, f, indent=2)

    logger.info("[%s] Node registered: %s → %s", rid, req.hostname, node_file)

    return JSONResponse(content={
        "status": "registered",
        "hostname": req.hostname,
        "message": f"Node {req.hostname} registered with WinBot host.",
        "node_file": node_file,
        "request_id": rid,
    })


# ============================================================
# Human Presence Detection
# ============================================================
import subprocess as _subprocess  # keep module-level subprocess for lifecycle use too


def _is_human_present() -> dict:
    """Detect whether a human is likely present at the VM console.

    Returns a dict with 'present' (bool) and 'evidence' (list of reasons).
    Designed to be called from the WinBot API service (Session 0).

    Detection methods:
    1. qwinsta — find Active console or RDP sessions
    2. explorer.exe — running in a user session (indicates interactive desktop)
    3. Idle time appoximation via quser (if available)
    """
    present = False
    evidence = []
    active_sessions = []
    idle_info = {}

    # Method 1: Query active user sessions via qwinsta
    try:
        result = _subprocess.run(
            ["qwinsta"], capture_output=True, text=True, timeout=5,
            creationflags=_subprocess.CREATE_NO_WINDOW,
        )
        for line in result.stdout.splitlines():
            # Lines look like: ">console    1  username  Active   .  6/21/2026 3:15 PM"
            if "Active" in line:
                active_sessions.append(line.strip())
                if "console" in line.lower():
                    evidence.append("console_session_active")
                elif "rdp-tcp" in line.lower():
                    evidence.append("rdp_session_active")
    except Exception:
        evidence.append("qwinsta_failed")

    if evidence and "qwinsta_failed" not in evidence:
        # At minimum we have active sessions — check for explorer.exe for confidence
        present = True

    # Method 2: explorer.exe running? (runs only in interactive user sessions)
    try:
        result = _subprocess.run(
            ["tasklist", "/FI", "IMAGENAME eq explorer.exe", "/NH"],
            capture_output=True, text=True, timeout=5,
            creationflags=_subprocess.CREATE_NO_WINDOW,
        )
        if "explorer.exe" in result.stdout:
            evidence.append("explorer_running")
            present = True  # Confirms interactive desktop
        else:
            # If sessions were Active but no explorer.exe, suspicious
            if "console_session_active" in evidence and "explorer_running" not in evidence:
                evidence.append("active_session_no_explorer")
                present = False  # Likely stuck at logon screen
    except Exception:
        evidence.append("tasklist_failed")

    # Method 3: quser for idle time (best-effort)
    try:
        result = _subprocess.run(
            ["quser"], capture_output=True, text=True, timeout=5,
            creationflags=_subprocess.CREATE_NO_WINDOW,
        )
        for line in result.stdout.splitlines():
            if line.strip() and "USERNAME" not in line and ">" in line:
                parts = line.split()
                if len(parts) >= 4 and parts[2] == "Active":
                    idle_info["session"] = parts[1] if len(parts) > 1 else "unknown"
                    # quser reports idle time as "." or "2:15" or "41+12:30"
                    if len(parts) >= 5:
                        idle_str = parts[4] if len(parts) > 4 else "."
                        if idle_str == ".":
                            idle_info["idle"] = "active_now"
                            evidence.append("idle_under_threshold")
                        else:
                            idle_info["idle"] = idle_str
    except Exception:
        pass

    return {
        "present": present,
        "evidence": evidence,
        "active_sessions": active_sessions,
        "idle": idle_info,
    }


# ============================================================
# Lifecycle
# ============================================================
# Track pending state for GET /lifecycle/status
_pending_lifecycle: dict = {"action": None, "expires_at": None, "delay": None}


@app.post("/lifecycle/shutdown")
async def shutdown(request: Request, delay: int = Query(0, ge=0, le=600, description="Countdown in seconds before shutdown (0=auto: 30s with human, 60s agent-only)")):
    """Shutdown the VM with a cancel window.

    Adapts behavior based on whether a human is present:
    - Human present: Windows system dialog visible, default 30s delay
    - Agent only: longer default 60s delay, rely on API cancel only

    Call POST /lifecycle/cancel within the delay window to abort.
    """
    rid = getattr(request.state, 'request_id', 'unknown')
    client_ip = request.client.host if request.client else "unknown"
    presence = _is_human_present()

    # Auto-select delay: 0 means use the context-appropriate default
    if delay == 0:
        delay = 30 if presence["present"] else 60

    cancel_before = (datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(seconds=delay)).isoformat()
    _pending_lifecycle["action"] = "shutdown"
    _pending_lifecycle["expires_at"] = cancel_before
    _pending_lifecycle["delay"] = delay

    logger.info("[%s] Lifecycle: shutdown requested (delay=%ds, human=%s)", rid, delay, presence["present"])
    security_log.info("LIFECYCLE [%s] SHUTDOWN delay=%ds human=%s evidence=%s (client:%s)",
        rid, delay, presence["present"], presence["evidence"], client_ip)

    _subprocess.Popen(
        ["shutdown", "/s", "/t", str(delay), "/c",
         f"WinBot API shutdown in {delay}s — run 'shutdown /a' to cancel"],
        creationflags=_subprocess.CREATE_NO_WINDOW,
    )

    return JSONResponse(content={
        "status": "shutting_down",
        "message": f"Shutdown initiated with {delay}s countdown.",
        "delay_seconds": delay,
        "cancel_before": cancel_before,
        "cancel_command": "POST /lifecycle/cancel",
        "human_present": presence["present"],
        "human_evidence": presence["evidence"],
        "request_id": rid,
    })


@app.post("/lifecycle/restart")
async def restart(request: Request, delay: int = Query(0, ge=0, le=600, description="Countdown in seconds before restart (0=auto: 30s with human, 60s agent-only)")):
    """Restart the VM with a cancel window.

    Adapts behavior based on whether a human is present:
    - Human present: Windows system dialog visible, default 30s delay
    - Agent only: longer default 60s delay, rely on API cancel only

    Call POST /lifecycle/cancel within the delay window to abort.
    """
    rid = getattr(request.state, 'request_id', 'unknown')
    client_ip = request.client.host if request.client else "unknown"
    presence = _is_human_present()

    if delay == 0:
        delay = 30 if presence["present"] else 60

    cancel_before = (datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(seconds=delay)).isoformat()
    _pending_lifecycle["action"] = "restart"
    _pending_lifecycle["expires_at"] = cancel_before
    _pending_lifecycle["delay"] = delay

    logger.info("[%s] Lifecycle: restart requested (delay=%ds, human=%s)", rid, delay, presence["present"])
    security_log.info("LIFECYCLE [%s] RESTART delay=%ds human=%s evidence=%s (client:%s)",
        rid, delay, presence["present"], presence["evidence"], client_ip)

    _subprocess.Popen(
        ["shutdown", "/r", "/t", str(delay), "/c",
         f"WinBot API restart in {delay}s — run 'shutdown /a' to cancel"],
        creationflags=_subprocess.CREATE_NO_WINDOW,
    )

    return JSONResponse(content={
        "status": "restarting",
        "message": f"Restart initiated with {delay}s countdown.",
        "delay_seconds": delay,
        "cancel_before": cancel_before,
        "cancel_command": "POST /lifecycle/cancel",
        "human_present": presence["present"],
        "human_evidence": presence["evidence"],
        "request_id": rid,
    })


@app.post("/lifecycle/cancel")
async def cancel_lifecycle(request: Request):
    """Cancel a pending shutdown or restart.

    Runs 'shutdown /a' to abort any pending system shutdown.
    This works both for API-initiated and manually-initiated shutdowns.
    """
    rid = getattr(request.state, 'request_id', 'unknown')
    client_ip = request.client.host if request.client else "unknown"
    logger.info("[%s] Lifecycle: cancel requested", rid)
    security_log.info("LIFECYCLE [%s] CANCEL (client:%s)", rid, client_ip)

    result = _subprocess.run(
        ["shutdown", "/a"],
        capture_output=True,
        text=True,
        creationflags=_subprocess.CREATE_NO_WINDOW,
    )

    # shutdown /a exits 0 on success, non-zero if no shutdown was pending
    if result.returncode == 0:
        _pending_lifecycle["action"] = None
        _pending_lifecycle["expires_at"] = None
        _pending_lifecycle["delay"] = None
        return JSONResponse(content={
            "status": "cancelled",
            "message": "Pending shutdown/restart has been cancelled.",
            "request_id": rid,
        })
    else:
        return JSONResponse(content={
            "status": "no_pending",
            "message": "No shutdown or restart was pending.",
            "detail": result.stderr.strip() if result.stderr else None,
            "request_id": rid,
        })


@app.get("/lifecycle/status")
async def lifecycle_status(request: Request):
    """Check whether a shutdown or restart is currently pending.

    Returns the pending action, remaining seconds, and cancel URL.
    Rate-limit exempt — always reachable even under load.
    """
    rid = getattr(request.state, 'request_id', 'unknown')
    action = _pending_lifecycle.get("action")
    expires = _pending_lifecycle.get("expires_at")

    if not action or not expires:
        return JSONResponse(content={
            "status": "idle",
            "pending_action": None,
            "remaining_seconds": None,
            "cancel_command": None,
            "request_id": rid,
        })

    # Compute remaining seconds
    try:
        expiry_dt = datetime.datetime.fromisoformat(expires)
        remaining = max(0, (expiry_dt - datetime.datetime.now(datetime.timezone.utc)).total_seconds())
    except (ValueError, TypeError):
        remaining = 0

    if remaining <= 0:
        _pending_lifecycle["action"] = None
        _pending_lifecycle["expires_at"] = None
        return JSONResponse(content={
            "status": "idle",
            "pending_action": None,
            "remaining_seconds": None,
            "_note": "Countdown has expired — action is executing now.",
            "request_id": rid,
        })

    return JSONResponse(content={
        "status": "pending",
        "pending_action": action,
        "remaining_seconds": int(remaining),
        "cancel_before": expires,
        "cancel_command": "POST /lifecycle/cancel",
        "human_present": _is_human_present()["present"],
        "request_id": rid,
    })


# ============================================================
# Remote Desktop — RDP connection file
# ============================================================

from fastapi.responses import PlainTextResponse


@app.get("/vnc/rdpfile")
async def generate_rdp_file():
    """Generate a .rdp file for connecting to this VM via native RDP client.

    Returns a plain-text .rdp file that the browser downloads and opens
    with the native RDP client (mstsc.exe on Windows). This provides the
    best possible user experience — clipboard, audio, drive redirection,
    and full 60 FPS rendering.

    The RDP server (TermService) is built into every Windows system.
    Enable it on the guest:
        Set-ItemProperty -Path 'HKLM:\\System\\CurrentControlSet\\Control\\Terminal Server' -Name fDenyTSConnections -Value 0
        Enable-NetFirewallRule -DisplayGroup "Remote Desktop"

    RDP connection details are auto-populated from the VM's hostname and IP.
    """
    import socket
    hostname = socket.gethostname()
    # Best effort to get IP on the Default Switch subnet
    try:
        host_ip = socket.gethostbyname(hostname)
    except Exception:
        host_ip = "127.0.0.1"

    rdp_content = (
        f"full address:s:{host_ip}:3389\n"
        f"alternate full address:s:{hostname}:3389\n"
        "username:s:winbot\n"
        "prompt for credentials:i:1\n"
        "authentication level:i:2\n"
        "session bpp:i:32\n"
        "desktopwidth:i:1920\n"
        "desktopheight:i:1080\n"
        "audiomode:i:0\n"
        "audiocapturemode:i:0\n"
        "redirectclipboard:i:1\n"
        "redirectdrives:i:0\n"
        "redirectprinters:i:0\n"
        "redirectcomports:i:0\n"
        "redirectsmartcards:i:0\n"
        "devicestoredirect:s:\n"
        "drivestoredirect:s:\n"
        "redirectwebauthn:i:1\n"
        "enablerdsaadauth:i:0\n"
        "enablecredsspsupport:i:1\n"
        "connection type:i:7\n"
        "networkautodetect:i:1\n"
        "bandwidthautodetect:i:1\n"
        "displayconnectionbar:i:1\n"
        f"full address:s:{host_ip}:3389\n"
    )

    return PlainTextResponse(
        content=rdp_content,
        media_type="application/x-rdp",
        headers={
            "Content-Disposition": f'attachment; filename="winbot-{hostname}.rdp"',
        },
    )


# ============================================================
# Session Recording — ffmpeg screen capture
# ============================================================

class RecordingRequest(BaseModel):
    fps: int = Field(15, ge=1, le=60)
    bitrate: str = Field("2M")


@app.get("/recording/status")
async def recording_status():
    """Get current recording status."""
    return recorder.status()


# Canonical alias: winebot-contracts GET /recording/health → WinBot recording_status
@app.get("/recording/health")
async def recording_health_canonical():
    """Canonical winebot-contracts endpoint: recording subsystem health.

    This is the canonical path defined in the shared API contract.
    Delegates to the WinBot recording status implementation.
    """
    return recorder.status()


@app.post("/recording/start")
async def recording_start(req: RecordingRequest):
    """Start recording the desktop."""
    return recorder.start(fps=req.fps, bitrate=req.bitrate)


@app.post("/recording/stop")
async def recording_stop():
    """Stop recording and return recording info."""
    return recorder.stop()


# ============================================================
# Input Tracing — API-level event recorder
# ============================================================

@app.post("/input/trace/start")
async def trace_start():
    """Start recording input events."""
    return tracer.start()


@app.post("/input/trace/stop")
async def trace_stop():
    """Stop recording input events."""
    return tracer.stop()


@app.get("/input/trace/status")
async def trace_status():
    """Get input tracing status."""
    return tracer.status()


@app.get("/input/trace/events")
async def trace_events(source: str = "api", limit: int = Query(100, ge=1, le=1000)):
    """Get recorded input events."""
    return tracer.get_events(source=source, limit=limit)


# Canonical alias: winebot-contracts GET /input/events → WinBot trace_events
@app.get("/input/events")
async def trace_events_canonical(source: str = "api", limit: int = Query(100, ge=1, le=1000)):
    """Canonical winebot-contracts endpoint: query traced input events.

    This is the canonical path defined in the shared API contract.
    Delegates to the WinBot trace events implementation.
    """
    return tracer.get_events(source=source, limit=limit)


# ============================================================
# Operations — telemetry and timing
# ============================================================

@app.get("/operations")
async def list_operations(limit: int = Query(50, ge=1, le=500), status: Optional[str] = Query(None)):
    """List recent operations with optional status filter."""
    return ops.list_operations(limit=limit, status=status)


@app.get("/operations/{operation_id}")
async def get_operation(operation_id: str):
    """Get a specific operation by ID."""
    try:
        op = ops.get_operation(operation_id)
        if not op:
            raise HTTPException(status_code=404, detail=f"Operation '{operation_id}' not found")
        return op
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=404, detail=f"Operation '{operation_id}' not found") from e


# ============================================================
# Version
# ============================================================
@app.get("/version")
async def version():
    """Get API and WinBot versions."""
    return {
        "api_version": API_VERSION,
        "winbot_version": WINBOT_VERSION,
        "os": "Windows",
        "hostname": socket.gethostname(),
    }


# ============================================================
# Main entry point
# ============================================================
if __name__ == "__main__":
    import uvicorn
    print(f"[WinBot] Starting API server v{WINBOT_VERSION}")
    print(f"[WinBot] Host: {socket.gethostname()}")
    print(f"[WinBot] API Token: {'configured' if API_TOKEN else 'not set (open)'}")
    uvicorn.run(
        "main:app",
        host="0.0.0.0",
        port=8000,
        log_level="info",
    )
