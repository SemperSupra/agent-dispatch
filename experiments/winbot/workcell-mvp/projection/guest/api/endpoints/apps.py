"""
WinBot Application Execution Endpoint
Launch Windows applications from the API, matching WineBot's /apps/run.
"""

import os
import subprocess


def _get_timeout() -> int:
    return int(os.environ.get("WINBOT_APP_TIMEOUT", "120"))
import shlex

from fastapi import HTTPException

# Safe paths allowed for app execution
ALLOWED_ROOTS = [
    r"C:\WinBot",
    r"C:\Windows",
    r"C:\Program Files",
    r"C:\Program Files (x86)",
    os.environ.get("TEMP", r"C:\Windows\Temp"),
    os.environ.get("USERPROFILE", r"C:\Users"),
]


def _is_path_allowed(path: str) -> bool:
    """Check if a path is within allowed directories."""
    if not path:
        return False
    abs_path = os.path.abspath(path)
    # Bare filenames are allowed (will be found via PATH)
    if not os.path.dirname(abs_path.replace(os.sep, '/')) or os.path.basename(path) == path:
        return True
    for root in ALLOWED_ROOTS:
        if os.path.commonpath([abs_path, root]) == root:
            return True
    return False


def run(path: str, args: str = "", detach: bool = False):
    """
    Launch a Windows application.

    Args:
        path: Path to executable (absolute or bare name)
        args: Command-line arguments string
        detach: If True, run in background and return immediately

    Returns:
        JSON response with status and output
    """
    if not _is_path_allowed(path):
        raise HTTPException(
            status_code=403,
            detail=f"Path not allowed: {path}. Must be under: {', '.join(ALLOWED_ROOTS)}"
        )

    # Build command
    cmd = [path]
    if args:
        cmd.extend(shlex.split(args, posix=False))

    try:
        if detach:
            # Run detached
            process = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                creationflags=subprocess.CREATE_NEW_PROCESS_GROUP,
            )
            return {
                "status": "detached",
                "pid": process.pid,
                "command": cmd,
            }
        else:
            # Run and wait
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=_get_timeout(),
                creationflags=subprocess.CREATE_NO_WINDOW,
            )

            if result.returncode == 0:
                return {
                    "status": "finished",
                    "exit_code": 0,
                    "stdout": result.stdout,
                    "stderr": result.stderr,
                }
            else:
                return {
                    "status": "failed",
                    "exit_code": result.returncode,
                    "stdout": result.stdout,
                    "stderr": result.stderr,
                }

    except subprocess.TimeoutExpired:
        return {
            "status": "timeout",
            "exit_code": None,
            "stdout": "",
            "stderr": "Command timed out after 60 seconds",
        }
    except FileNotFoundError:
        raise HTTPException(
            status_code=404,
            detail=f"Executable not found: {path}"
        )
    except Exception as e:
        raise HTTPException(
            status_code=500,
            detail=f"Failed to run app: {str(e)}"
        )
