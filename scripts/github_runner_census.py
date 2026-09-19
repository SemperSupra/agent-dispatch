#!/usr/bin/env python3
"""Passive, public-safe census of a GitHub-hosted Actions runner.

The probe is intentionally read-only. It records resource and capability
presence without installing packages, opening devices, starting services, or
dumping environment variables.
"""
from __future__ import annotations

import argparse
import datetime as dt
import json
import os
import pathlib
import platform
import re
import shutil
import subprocess
import tempfile
from typing import Any

SCHEMA = "github-runner-capability/v1"
PROBE_VERSION = "public-passive/1"

def _run_text(argv: list[str], timeout: int = 5) -> str | None:
    try:
        cp = subprocess.run(argv, check=False, capture_output=True, text=True, timeout=timeout)
    except (OSError, subprocess.SubprocessError):
        return None
    if cp.returncode != 0:
        return None
    return cp.stdout.strip()

def _linux_meminfo() -> tuple[int | None, int | None]:
    path = pathlib.Path("/proc/meminfo")
    if not path.exists():
        return None, None
    fields: dict[str, int] = {}
    for line in path.read_text(errors="replace").splitlines():
        m = re.match(r"^([^:]+):\s+(\d+)\s+kB$", line)
        if m:
            fields[m.group(1)] = int(m.group(2)) * 1024
    return fields.get("MemTotal"), fields.get("MemAvailable")

def _mac_memory() -> tuple[int | None, int | None]:
    raw_total = _run_text(["sysctl", "-n", "hw.memsize"])
    total = int(raw_total) if raw_total and raw_total.isdigit() else None
    raw = _run_text(["vm_stat"])
    if not raw:
        return total, None
    page_match = re.search(r"page size of (\d+) bytes", raw)
    page_size = int(page_match.group(1)) if page_match else 4096
    pages = 0
    for key in ("Pages free", "Pages inactive", "Pages speculative"):
        m = re.search(rf"^{re.escape(key)}:\s+(\d+)\.", raw, re.MULTILINE)
        if m:
            pages += int(m.group(1))
    return total, pages * page_size if pages else None

def _cpu_model(system: str) -> str | None:
    if system == "Linux":
        path = pathlib.Path("/proc/cpuinfo")
        if path.exists():
            for line in path.read_text(errors="replace").splitlines():
                if ":" in line:
                    key, value = line.split(":", 1)
                    if key.strip() in {"model name", "Hardware", "Processor"} and value.strip():
                        return value.strip()
    if system == "Darwin":
        return (_run_text(["sysctl", "-n", "machdep.cpu.brand_string"])
                or _run_text(["sysctl", "-n", "hw.model"]))
    return platform.processor() or None

def _storage() -> list[dict[str, Any]]:
    raw = _run_text(["df", "-Pk"])
    rows: list[dict[str, Any]] = []
    seen: set[tuple[str, str]] = set()
    if raw:
        for line in raw.splitlines()[1:]:
            parts = line.split()
            if len(parts) < 6 or not parts[1].isdigit():
                continue
            filesystem, blocks, _used, available, _capacity = parts[:5]
            mount = " ".join(parts[5:])
            key = (filesystem, mount)
            if key in seen:
                continue
            seen.add(key)
            rows.append({
                "mount": mount,
                "filesystem": filesystem,
                "total_bytes": int(blocks) * 1024,
                "free_bytes": int(available) * 1024,
            })
    if not rows:
        for mount in {str(pathlib.Path.cwd()), tempfile.gettempdir()}:
            try:
                usage = shutil.disk_usage(mount)
            except OSError:
                continue
            rows.append({
                "mount": mount,
                "filesystem": None,
                "total_bytes": usage.total,
                "free_bytes": usage.free,
            })
    return rows

def _presence_capability(name: str, present: bool, evidence: Any = None,
                         *, installed: bool | None = None) -> dict[str, Any]:
    return {
        "name": name,
        "advertised": None,
        "observed": present,
        "installed": present if installed is None else installed,
        "callable": None,
        "exercised": False,
        "oracleSatisfied": False,
        "classification": "INCONCLUSIVE" if present else "NEGATIVE_OBSERVATION",
        "reason": "present; passive census does not exercise it" if present else "not observed",
        "evidence": evidence,
    }

def build_receipt(requested_label: str | None = None) -> dict[str, Any]:
    system = platform.system()
    machine = platform.machine()
    if system == "Linux":
        mem_total, mem_available = _linux_meminfo()
    elif system == "Darwin":
        mem_total, mem_available = _mac_memory()
    else:
        mem_total = mem_available = None

    capabilities: list[dict[str, Any]] = []
    for command in (
        "docker", "podman", "containerd", "qemu-system-x86_64",
        "qemu-system-aarch64", "clang", "gcc", "xcodebuild", "xcrun",
    ):
        path = shutil.which(command)
        capabilities.append(_presence_capability(f"command:{command}", path is not None, path))

    if system == "Linux":
        for device in ("/dev/kvm", "/dev/dri", "/dev/fuse", "/dev/net/tun"):
            p = pathlib.Path(device)
            capabilities.append(_presence_capability(f"device:{device}", p.exists(), str(p) if p.exists() else None,
                                                     installed=None))
        cgroup_v2 = pathlib.Path("/sys/fs/cgroup/cgroup.controllers").exists()
        capabilities.append(_presence_capability("linux:cgroup-v2", cgroup_v2,
                                                 "/sys/fs/cgroup/cgroup.controllers" if cgroup_v2 else None,
                                                 installed=None))
        binfmt = pathlib.Path("/proc/sys/fs/binfmt_misc").exists()
        capabilities.append(_presence_capability("linux:binfmt-misc", binfmt,
                                                 "/proc/sys/fs/binfmt_misc" if binfmt else None,
                                                 installed=None))
    elif system == "Darwin":
        for framework in ("Hypervisor.framework", "Virtualization.framework", "Metal.framework"):
            p = pathlib.Path("/System/Library/Frameworks") / framework
            capabilities.append(_presence_capability(f"macos:framework:{framework}", p.exists(),
                                                     str(p) if p.exists() else None,
                                                     installed=None))
        rosetta = pathlib.Path("/Library/Apple/usr/share/rosetta/rosetta").exists()
        capabilities.append(_presence_capability("macos:rosetta", rosetta,
                                                 "/Library/Apple/usr/share/rosetta/rosetta" if rosetta else None,
                                                 installed=None))

    privileged = None
    if hasattr(os, "geteuid"):
        privileged = os.geteuid() == 0

    environment = {
        "github_actions": os.environ.get("GITHUB_ACTIONS") == "true",
        "runner_environment": os.environ.get("RUNNER_ENVIRONMENT"),
        "runner_temp_present": bool(os.environ.get("RUNNER_TEMP")),
        "runner_tool_cache_present": bool(os.environ.get("RUNNER_TOOL_CACHE")),
        "cgroup_version": 2 if pathlib.Path("/sys/fs/cgroup/cgroup.controllers").exists() else (
            1 if pathlib.Path("/sys/fs/cgroup").exists() else None
        ),
    }

    timestamp = dt.datetime.now(dt.timezone.utc).isoformat().replace("+00:00", "Z")
    return {
        "schema": SCHEMA,
        "provenance": {
            "requested_label": requested_label or os.environ.get("CENSUS_REQUESTED_LABEL") or "unknown",
            "repository_visibility": os.environ.get("CENSUS_REPOSITORY_VISIBILITY", "public"),
            "workflow_sha": os.environ.get("GITHUB_SHA", ""),
            "run_id": os.environ.get("GITHUB_RUN_ID", ""),
            "run_attempt": os.environ.get("GITHUB_RUN_ATTEMPT", ""),
            "probe_version": PROBE_VERSION,
            "timestamp_utc": timestamp,
            "image_os": os.environ.get("ImageOS"),
            "image_version": os.environ.get("ImageVersion"),
        },
        "runner": {
            "system": system,
            "release": platform.release(),
            "machine": machine,
            "architecture": machine,
            "runner_os": os.environ.get("RUNNER_OS"),
            "runner_arch": os.environ.get("RUNNER_ARCH"),
            "privileged": privileged,
        },
        "resources": {
            "cpu": {
                "logical_processors": os.cpu_count(),
                "model": _cpu_model(system),
            },
            "memory": {
                "total_bytes": mem_total,
                "available_bytes": mem_available,
            },
            "storage": _storage(),
        },
        "environment": environment,
        "capabilities": capabilities,
        "observations": [],
        "warnings": [
            "passive presence is not proof of callability or workload suitability",
            "resource values are observations for this job, not platform guarantees",
        ],
    }

def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--out", required=True)
    parser.add_argument("--label")
    args = parser.parse_args()
    receipt = build_receipt(args.label)
    path = pathlib.Path(args.out)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(receipt, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(f"CAPABILITY_RECEIPT={path}")
    print(json.dumps(receipt, indent=2, sort_keys=True))
    return 0

if __name__ == "__main__":
    raise SystemExit(main())
