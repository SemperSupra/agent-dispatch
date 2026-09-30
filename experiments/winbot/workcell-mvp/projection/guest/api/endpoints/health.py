"""
WinBot Health Endpoints
Mirrors WineBot's /health endpoints for system, tools, storage reporting.
"""

import os
import platform
import shutil
import subprocess
import sys
from datetime import datetime

import psutil


def get_tool_check(tool_name: str, paths: list, version_cmd: str = None):
    """Check if a tool is installed and get its version."""
    exe_path = None
    for p in paths:
        if os.path.exists(p):
            exe_path = p
            break
    if not exe_path:
        found = shutil.which(tool_name + ".exe") or shutil.which(tool_name)
        if found:
            exe_path = found

    if not exe_path:
        return {"installed": False, "path": None, "version": None}

    version = None
    if version_cmd:
        try:
            result = subprocess.run(
                [exe_path] + version_cmd.split(),
                capture_output=True, text=True, timeout=10
            )
            version = (result.stdout + result.stderr).strip().split("\n")[0]
        except Exception:
            version = "unknown"

    return {"installed": True, "path": exe_path, "version": version}


def get_health_summary():
    """Top-level health summary matching WineBot's /health."""
    tools = get_tools_health()
    storage = get_storage_health()
    get_system_health()

    all_tools_ok = all(t["installed"] for t in tools["tools"].values())

    return {
        "status": "ok" if all_tools_ok else "degraded",
        "hostname": platform.node(),
        "os": f"Windows {platform.release()} ({platform.version()})",
        "uptime_seconds": int(psutil.boot_time()),
        "tools": tools,
        "storage": storage,
        "memory": {
            "total_gb": round(psutil.virtual_memory().total / (1024**3), 1),
            "available_gb": round(psutil.virtual_memory().available / (1024**3), 1),
            "percent_used": psutil.virtual_memory().percent,
        },
        "python_version": sys.version,
    }


def get_system_health():
    """System uptime, CPU, memory details."""
    return {
        "hostname": platform.node(),
        "os": platform.system(),
        "os_version": platform.version(),
        "os_release": platform.release(),
        "cpu_count": psutil.cpu_count(),
        "cpu_percent": psutil.cpu_percent(interval=0.5),
        "memory": {
            "total_bytes": psutil.virtual_memory().total,
            "available_bytes": psutil.virtual_memory().available,
            "percent_used": psutil.virtual_memory().percent,
        },
        "boot_time": datetime.fromtimestamp(psutil.boot_time()).isoformat(),
        "uptime_seconds": int(datetime.now().timestamp() - psutil.boot_time()),
    }


def get_system_info():
    """Detailed system information."""
    return {
        "hostname": platform.node(),
        "os": f"{platform.system()} {platform.release()}",
        "architecture": platform.machine(),
        "processor": platform.processor(),
        "cpu_count_physical": psutil.cpu_count(logical=False),
        "cpu_count_logical": psutil.cpu_count(logical=True),
        "memory_total_gb": round(psutil.virtual_memory().total / (1024**3), 1),
        "disks": [
            {
                "device": p.device,
                "mountpoint": p.mountpoint,
                "fstype": p.fstype,
                "total_gb": round(psutil.disk_usage(p.mountpoint).total / (1024**3), 1),
                "used_gb": round(psutil.disk_usage(p.mountpoint).used / (1024**3), 1),
                "free_gb": round(psutil.disk_usage(p.mountpoint).free / (1024**3), 1),
            }
            for p in psutil.disk_partitions()
            if p.fstype and 'cdrom' not in p.opts
        ],
        "network": [
            {"name": name, "addresses": [
                a.address for a in addrs if a.family.name == "AF_INET"
            ]}
            for name, addrs in psutil.net_if_addrs().items()
            if any(a.family.name == "AF_INET" for a in addrs)
        ],
        "python_version": sys.version,
    }


def get_tools_health():
    """Check presence and versions of all WinBot tools."""
    tools = {
        "autoit": get_tool_check("autoit", [
            r"C:\Program Files (x86)\AutoIt3\AutoIt3.exe",
            r"C:\Program Files\AutoIt3\AutoIt3.exe",
        ]),
        "ahk": get_tool_check("ahk", [
            r"C:\Program Files\AutoHotkey\AutoHotkey.exe",
            r"C:\Program Files\AutoHotkey\AutoHotkeyU64.exe",
        ]),
        "python": get_tool_check("python", [
            r"C:\Python313\python.exe",
        ], version_cmd="--version"),
        "winspy": get_tool_check("winspy", [
            r"C:\WinBot\tools\WinSpy\windowspy.exe",
        ]),
        "nssm": get_tool_check("nssm", [
            r"C:\ProgramData\chocolatey\bin\nssm.exe",
        ]),
    }

    return {
        "all_ok": all(t["installed"] for t in tools.values()),
        "tools": tools,
    }


def get_storage_health():
    """Check disk space for WinBot directories."""
    dirs = [
        r"C:\WinBot",
        r"C:\WinBot\sessions",
        r"C:\WinBot\logs",
        os.environ.get("TEMP", r"C:\Windows\Temp"),
    ]

    result = {}
    for d in dirs:
        if os.path.exists(d):
            try:
                usage = psutil.disk_usage(d)
                result[d] = {
                    "total_gb": round(usage.total / (1024**3), 1),
                    "free_gb": round(usage.free / (1024**3), 1),
                    "percent_used": usage.percent,
                    "writable": os.access(d, os.W_OK),
                }
            except Exception:
                result[d] = {"error": "Could not get disk usage"}
        else:
            result[d] = {"exists": False}

    return {"directories": result}
