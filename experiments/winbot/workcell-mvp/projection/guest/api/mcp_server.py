"""WinBot MCP Server — Model Context Protocol server for LLM agent control.
Integrated with the control broker for human-in-the-loop safety.
Compatible with WineBot's planned MCP interface for agent substitutability.

Run: python mcp_server.py
Uses the FastMCP library. Each tool enforces broker.check_access() before executing.
"""

import os
import sys

# Ensure api directory is on path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from core.broker import broker
from endpoints import apps, automation, health, input_ep, screenshot, windows

# Try FastMCP; fall back with clear error
try:
    from mcp.server.fastmcp import FastMCP
except ImportError:
    print("ERROR: FastMCP not installed. Run: pip install mcp")
    print("See: https://github.com/modelcontextprotocol/python-sdk")
    sys.exit(1)

# API base URL for the WinBot REST API (this MCP server runs alongside FastAPI)
API_BASE = os.environ.get("WINBOT_API_URL", "http://127.0.0.1:8000")

mcp = FastMCP("WinBot")


async def _check_agent_access():
    """Enforce broker control policy before tool execution."""
    allowed = await broker.check_access()
    if not allowed:
        raise PermissionError(
            "Agent does not have control. Grant control via POST /control/sessions/{id}/control/grant"
        )


# ── Health ──

@mcp.tool()
async def health_check() -> dict:
    """Check WinBot system health — tools, storage, connectivity."""
    await _check_agent_access()
    return health.get_health_summary()


@mcp.tool()
async def system_info() -> dict:
    """Get detailed system information."""
    await _check_agent_access()
    return health.get_system_info()


# ── Screenshot ──

@mcp.tool()
async def take_screenshot(format: str = "png") -> dict:
    """Capture a screenshot of the VM desktop. Returns base64 image data."""
    await _check_agent_access()
    return screenshot.capture(format=format)


# ── Window Management ──

@mcp.tool()
async def list_windows() -> dict:
    """List all visible windows on the desktop."""
    await _check_agent_access()
    return windows.list_windows()


@mcp.tool()
async def focus_window(title: str, substring: bool = True) -> dict:
    """Focus a window by title match (substring by default)."""
    await _check_agent_access()
    return windows.focus_window(title, substring)


@mcp.tool()
async def inspect_window(title: str = "", handle: str = "") -> dict:
    """Inspect window properties by title or hex handle."""
    await _check_agent_access()
    return windows.inspect_window(title if title else None, handle if handle else None)


# ── Input ──

@mcp.tool()
async def mouse_click(x: int, y: int, button: int = 1, clicks: int = 1) -> dict:
    """Click at screen coordinates. button=1 left, 2 middle, 3 right."""
    await _check_agent_access()
    return input_ep.mouse_click(x, y, button, clicks, 0.1)


@mcp.tool()
async def mouse_move(x: int, y: int) -> dict:
    """Move mouse to screen coordinates."""
    await _check_agent_access()
    return input_ep.mouse_move(x, y)


@mcp.tool()
async def keyboard_type(text: str, interval: float = 0.05) -> dict:
    """Type text at the current cursor position."""
    await _check_agent_access()
    return input_ep.keyboard_type(text, interval)


@mcp.tool()
async def keyboard_press(keys: str) -> dict:
    """Press a key combination (e.g., 'ctrl+c', 'alt+tab')."""
    await _check_agent_access()
    return input_ep.keyboard_press(keys)


# ── Applications ──

@mcp.tool()
async def run_app(path: str, args: str = "", detach: bool = False) -> dict:
    """Launch a Windows application."""
    await _check_agent_access()
    return apps.run(path, args, detach)


# ── Automation Scripts ──

@mcp.tool()
async def run_python_script(script: str) -> dict:
    """Execute a Python script on the VM."""
    await _check_agent_access()
    return automation.run_python(script)


@mcp.tool()
async def run_ahk_script(script: str) -> dict:
    """Execute an AutoHotkey script."""
    await _check_agent_access()
    return automation.run_ahk(script)


@mcp.tool()
async def run_autoit_script(script: str) -> dict:
    """Execute an AutoIt script."""
    await _check_agent_access()
    return automation.run_autoit(script)


# ── Control Policy ──

@mcp.tool()
async def get_control_state() -> dict:
    """Get current agent control state (mode, lease, user intent)."""
    state = broker.get_state()
    return {
        "control_mode": state.control_mode.value,
        "interactive": state.interactive,
        "user_intent": state.user_intent.value,
        "agent_status": state.agent_status.value,
        "effective_control_mode": state.effective_control_mode.value,
        "lease_expiry": state.lease_expiry,
    }


@mcp.tool()
async def renew_agent_control(lease_seconds: int = 300) -> dict:
    """Renew the agent's control lease for N more seconds."""
    await broker.renew_agent(lease_seconds)
    state = broker.get_state()
    return {"lease_expiry": state.lease_expiry, "control_mode": state.control_mode.value}


# ── Tool deployment ──

@mcp.tool()
async def deploy_loadout(template: str = "default", async_mode: bool = False) -> dict:
    """Install tools on this VM using a loadout template. Available templates:
    default (basic automation), re-tools (reverse engineering), full (everything).
    Set async_mode=true to return immediately with an operation_id for polling
    via GET /operations/{operation_id}."""
    await _check_agent_access()
    from endpoints.operations import ops
    op_id = ops.start("mcp.deploy_loadout", {"template": template})
    try:
        import os
        import subprocess
        script = os.path.join(os.path.dirname(__file__), "..", "tools", "deploy-loadout.ps1")
        if not os.path.exists(script):
            ops.complete(op_id, "deploy-loadout.ps1 not found")
            return {"status": "error", "operation_id": op_id, "message": "Script not found"}
        if async_mode:
            # Fire and forget — caller polls /operations/{op_id}
            subprocess.Popen(
                ["powershell", "-NoProfile", "-ExecutionPolicy", "Bypass", "-File", script,
                 "-Template", template],
                creationflags=subprocess.CREATE_NO_WINDOW,
            )
            return {"status": "started", "operation_id": op_id, "message": f"Deployment started. Poll GET /operations/{op_id} for status."}
        result = subprocess.run(
            ["powershell", "-NoProfile", "-ExecutionPolicy", "Bypass", "-File", script,
             "-Template", template],
            capture_output=True, text=True, timeout=600,
            creationflags=subprocess.CREATE_NO_WINDOW,
        )
        status = "completed" if result.returncode == 0 else "failed"
        ops.complete(op_id, None if status == "completed" else result.stderr[-500:])
        return {
            "status": status, "operation_id": op_id,
            "exit_code": result.returncode,
            "stdout": result.stdout[-2000:] if result.stdout else "",
        }
    except subprocess.TimeoutExpired:
        ops.complete(op_id, "timeout after 10 minutes")
        return {"status": "timeout", "operation_id": op_id, "message": "Deployment exceeded 10 minutes"}
    except Exception as e:
        ops.complete(op_id, str(e))
        return {"status": "error", "operation_id": op_id, "message": str(e)}


@mcp.tool()
async def install_tool(tool_name: str) -> dict:
    """Install a specific tool on this VM by name (e.g., 'autoit', 'nssm', 'ffmpeg').
    Call GET /health/tool_catalog to see available tools."""
    await _check_agent_access()
    import os
    import subprocess
    script = os.path.join(os.path.dirname(__file__), "..", "tools", "deploy-loadout.ps1")
    if not os.path.exists(script):
        return {"status": "error", "message": "deploy-loadout.ps1 not found"}
    try:
        result = subprocess.run(
            ["powershell", "-NoProfile", "-ExecutionPolicy", "Bypass", "-File", script,
             "-Tool", tool_name],
            capture_output=True, text=True, timeout=300,
            creationflags=subprocess.CREATE_NO_WINDOW,
        )
        return {
            "status": "completed" if result.returncode == 0 else "failed",
            "tool": tool_name,
            "stdout": result.stdout[-2000:] if result.stdout else "",
        }
    except subprocess.TimeoutExpired:
        return {"status": "timeout", "message": "Tool installation timed out"}
    except Exception as e:
        return {"status": "error", "message": str(e)}


# ── Main ──

if __name__ == "__main__":
    print(f"WinBot MCP Server starting (API: {API_BASE})")
    print(f"Broker mode: {broker.get_state().effective_control_mode.value}")
    mcp.run()
