"""
WinBot Automation Endpoints
Execute AutoHotkey, AutoIt, and Python scripts -- mirrors WineBot's /run/ahk, /run/autoit, /run/python.
"""

import hashlib
import logging
import os
import shutil
import subprocess
import sys
import tempfile


def _get_timeout() -> int:
    return int(os.environ.get("WINBOT_SCRIPT_TIMEOUT", "120"))

from fastapi import HTTPException

_security_log = logging.getLogger("winbot.security")

# Maximum output size from script execution (10 MB) -- prevents OOM from
# runaway processes generating excessive stdout/stderr
_MAX_OUTPUT_SIZE = 10 * 1024 * 1024

logger = logging.getLogger("winbot.api")


def _truncate_output(output: str, max_bytes: int = _MAX_OUTPUT_SIZE) -> str:
    """Truncate output to prevent OOM from runaway process output."""
    encoded = output.encode("utf-8")
    if len(encoded) <= max_bytes:
        return output
    # Truncate at max_bytes boundary, append truncation notice
    truncated = encoded[:max_bytes].decode("utf-8", errors="replace")
    return truncated + f"\n... [output truncated at {max_bytes // 1024 // 1024} MB]"


def _find_ahk():
    """Find AutoHotkey executable. Checks v2, v1.1, Chocolatey, and PATH."""
    paths = [
        # AHK v2 (Chocolatey installs to Program Files\AutoHotkey\v2)
        r"C:\Program Files\AutoHotkey\v2\AutoHotkey.exe",
        # AHK v1.1
        r"C:\Program Files\AutoHotkey\AutoHotkey.exe",
        r"C:\Program Files\AutoHotkey\AutoHotkeyU64.exe",
        r"C:\Program Files\AutoHotkey\v1.1\AutoHotkey.exe",
        # Chocolatey install path (via choco install autohotkey)
        r"C:\ProgramData\chocolatey\lib\autohotkey\tools\AutoHotkey.exe",
    ]
    for p in paths:
        if os.path.exists(p):
            return p
    found = shutil.which("AutoHotkey.exe") or shutil.which("AutoHotkey64.exe")
    if found:
        return found
    raise HTTPException(status_code=500, detail="AutoHotkey not found. Run install-autohotkey.ps1 first.")


def _find_autoit():
    """Find AutoIt executable. Checks standard paths, Chocolatey, and PATH."""
    paths = [
        # Standard install locations
        r"C:\Program Files (x86)\AutoIt3\AutoIt3.exe",
        r"C:\Program Files\AutoIt3\AutoIt3.exe",
        # Chocolatey install path
        r"C:\ProgramData\chocolatey\lib\autoit\tools\AutoIt3\AutoIt3.exe",
    ]
    for p in paths:
        if os.path.exists(p):
            return p
    found = shutil.which("AutoIt3.exe")
    if found:
        return found
    raise HTTPException(status_code=500, detail="AutoIt not found. Run install-autoit.ps1 first.")


def run_ahk(script: str):
    """
    Execute an AutoHotkey script.

    Args:
        script: AHK script content (e.g., "MsgBox, Hello from WinBot API")

    Returns:
        JSON with status and stdout
    """
    ahk_exe = _find_ahk()

    _security_log.info("AHK_EXEC script_hash=%s length=%d",
        hashlib.sha256(script.encode()).hexdigest()[:16], len(script))

    # Write script to temp file
    fd, script_path = tempfile.mkstemp(suffix=".ahk", prefix="winbot_")
    try:
        with os.fdopen(fd, 'w', encoding='utf-8') as f:
            f.write(script)

        result = subprocess.run(
            [ahk_exe, script_path],
            capture_output=True,
            text=True,
            timeout=_get_timeout(),
            creationflags=subprocess.CREATE_NO_WINDOW,
        )

        return {
            "status": "ok",
            "stdout": _truncate_output(result.stdout),
            "stderr": _truncate_output(result.stderr),
            "exit_code": result.returncode,
        }
    except subprocess.TimeoutExpired:
        return {
            "status": "timeout",
            "stdout": "",
            "stderr": "Script timed out",
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"AHK execution failed: {str(e)}")
    finally:
        try:
            os.unlink(script_path)
        except Exception:
            pass


def run_autoit(script: str):
    """
    Execute an AutoIt script.

    Args:
        script: AutoIt script content (e.g., 'MsgBox(0, "Title", "Hello")')

    Returns:
        JSON with status and stdout
    """
    autoit_exe = _find_autoit()

    _security_log.info("AUTOIT_EXEC script_hash=%s length=%d",
        hashlib.sha256(script.encode()).hexdigest()[:16], len(script))

    # Write script to temp file
    fd, script_path = tempfile.mkstemp(suffix=".au3", prefix="winbot_")
    try:
        with os.fdopen(fd, 'w', encoding='utf-8') as f:
            f.write(script)

        result = subprocess.run(
            [autoit_exe, "/AutoIt3ExecuteScript", script_path],
            capture_output=True,
            text=True,
            timeout=_get_timeout(),
            creationflags=subprocess.CREATE_NO_WINDOW,
        )

        return {
            "status": "ok",
            "stdout": _truncate_output(result.stdout),
            "stderr": _truncate_output(result.stderr),
            "exit_code": result.returncode,
        }
    except subprocess.TimeoutExpired:
        return {
            "status": "timeout",
            "stdout": "",
            "stderr": "Script timed out",
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"AutoIt execution failed: {str(e)}")
    finally:
        try:
            os.unlink(script_path)
        except Exception:
            pass


def run_python(script: str):
    """
    Execute Python code.

    Args:
        script: Python code to execute

    Returns:
        JSON with status and stdout
    """
    _security_log.info("PYTHON_EXEC script_hash=%s length=%d",
        hashlib.sha256(script.encode()).hexdigest()[:16], len(script))
    try:
        result = subprocess.run(
            [sys.executable, "-c", script],
            capture_output=True,
            text=True,
            timeout=_get_timeout(),
            creationflags=subprocess.CREATE_NO_WINDOW,
        )

        return {
            "status": "ok" if result.returncode == 0 else "failed",
            "stdout": _truncate_output(result.stdout),
            "stderr": _truncate_output(result.stderr),
            "exit_code": result.returncode,
        }
    except subprocess.TimeoutExpired:
        return {
            "status": "timeout",
            "stdout": "",
            "stderr": "Script timed out",
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Python execution failed: {str(e)}")
