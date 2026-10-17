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
PROBE_VERSION = "public-passive/2"

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

def _windows_hyperv_capabilities() -> list[dict[str, Any]]:
    """Passive Windows virtualization control-plane observations."""
    ps = shutil.which("powershell") or shutil.which("pwsh")
    if not ps:
        return [_presence_capability("windows:hyperv-control-plane", False)]

    script = r"""
$ErrorActionPreference = 'SilentlyContinue'
$cs = Get-CimInstance Win32_ComputerSystem
$vmhost = Get-Command Get-VMHost -ErrorAction SilentlyContinue
$vmswitch = Get-Command Get-VMSwitch -ErrorAction SilentlyContinue
$vmms = Get-Service vmms -ErrorAction SilentlyContinue
[pscustomobject]@{
  HypervisorPresent = [bool]$cs.HypervisorPresent
  GetVMHostPresent = [bool]$vmhost
  GetVMSwitchPresent = [bool]$vmswitch
  VMMSPresent = [bool]$vmms
  VMMSStatus = if ($vmms) { [string]$vmms.Status } else { $null }
} | ConvertTo-Json -Compress
"""
    raw = _run_text([ps, "-NoProfile", "-NonInteractive", "-Command", script])
    if not raw:
        return [_presence_capability("windows:hyperv-control-plane", False)]
    try:
        evidence = json.loads(raw)
    except json.JSONDecodeError:
        return [_presence_capability("windows:hyperv-control-plane", False)]
    present = bool(evidence.get("GetVMHostPresent") or evidence.get("GetVMSwitchPresent") or evidence.get("VMMSPresent"))
    return [_presence_capability("windows:hyperv-control-plane", present, evidence, installed=None)]


def _windows_additional_capabilities() -> list[dict[str, Any]]:
    """Passive Windows desktop, VHD, WSL, and daemon observations."""
    ps = shutil.which("powershell") or shutil.which("pwsh")
    if not ps:
        return []
    script = r"""
$ErrorActionPreference = 'SilentlyContinue'
$interactive = [System.Environment]::UserInteractive
$mountVhd = [bool](Get-Command Mount-VHD -ErrorAction SilentlyContinue)
$dockerSvc = Get-Service docker -ErrorAction SilentlyContinue
$dockerStatus = if ($dockerSvc) { [string]$dockerSvc.Status } else { $null }
$wsl = [bool](Get-Command wsl -ErrorAction SilentlyContinue)
[pscustomobject]@{
  UserInteractive = [bool]$interactive
  MountVHDPresent = [bool]$mountVhd
  DockerServicePresent = [bool]$dockerSvc
  DockerServiceStatus = $dockerStatus
  WSLPresent = [bool]$wsl
} | ConvertTo-Json -Compress
"""
    raw = _run_text([ps, "-NoProfile", "-NonInteractive", "-Command", script], timeout=8)
    if not raw:
        return [
            _presence_capability("windows:interactive-session", False),
            _presence_capability("windows:vhd-cmdlet", False),
            _presence_capability("windows:docker-daemon", False),
            _presence_capability("windows:wsl", False),
        ]
    try:
        ev = json.loads(raw)
    except json.JSONDecodeError:
        return [
            _presence_capability("windows:interactive-session", False),
            _presence_capability("windows:vhd-cmdlet", False),
            _presence_capability("windows:docker-daemon", False),
            _presence_capability("windows:wsl", False),
        ]
    return [
        _presence_capability("windows:interactive-session", bool(ev.get("UserInteractive")), ev),
        _presence_capability("windows:vhd-cmdlet", bool(ev.get("MountVHDPresent")), ev),
        _presence_capability("windows:docker-daemon", bool(ev.get("DockerServicePresent")), ev),
        _presence_capability("windows:wsl", bool(ev.get("WSLPresent")), ev),
    ]


def _linux_dev_shm_capability() -> dict[str, Any]:
    """Observe /dev/shm tmpfs RAM-disk presence, size, and writeability."""
    shm = pathlib.Path("/dev/shm")
    if not shm.exists() or not shm.is_dir():
        return _presence_capability("linux:dev-shm-tmpfs", False)
    try:
        usage = shutil.disk_usage(str(shm))
        is_writable = os.access(str(shm), os.W_OK)
        evidence = {
            "path": str(shm),
            "total_bytes": usage.total,
            "free_bytes": usage.free,
            "writable": is_writable,
        }
        return _presence_capability("linux:dev-shm-tmpfs", True, evidence, installed=True)
    except OSError as e:
        return _presence_capability("linux:dev-shm-tmpfs", True, {"error": str(e)}, installed=True)


def _linux_kvm_access_capabilities() -> list[dict[str, Any]]:
    """Observe user-space and passwordless sudo accessibility of /dev/kvm."""
    p = pathlib.Path("/dev/kvm")
    if not p.exists():
        return [
            _presence_capability("linux:kvm-user-accessible", False),
            _presence_capability("linux:kvm-sudo-accessible", False),
        ]
    user_acc = os.access(str(p), os.R_OK | os.W_OK)
    # Check passwordless sudo access safely without device modification
    sudo_acc = False
    try:
        cp = subprocess.run(
            ["sudo", "-n", "test", "-r", "/dev/kvm", "-a", "-w", "/dev/kvm"],
            check=False,
            capture_output=True,
            timeout=5,
        )
        sudo_acc = cp.returncode == 0
    except (OSError, subprocess.SubprocessError):
        sudo_acc = False

    return [
        _presence_capability("linux:kvm-user-accessible", user_acc, {"user_rw": user_acc}, installed=user_acc),
        _presence_capability("linux:kvm-sudo-accessible", sudo_acc, {"sudo_rw": sudo_acc}, installed=sudo_acc),
    ]


def _docker_daemon_capability() -> dict[str, Any]:
    """Distinguish functional Docker daemon presence from CLI-only installation."""
    docker = shutil.which("docker")
    if not docker:
        return _presence_capability("docker:daemon-accessible", False)
    ver = _run_text([docker, "version", "--format", "{{.Server.Version}}"], timeout=4)
    if ver:
        return _presence_capability("docker:daemon-accessible", True, {"server_version": ver}, installed=True)
    return _presence_capability(
        "docker:daemon-accessible", False, "Docker CLI present but daemon unreachable", installed=False
    )


def _android_capabilities() -> list[dict[str, Any]]:
    """Observe Android SDK environment, adb, and emulator availability."""
    android_home = os.environ.get("ANDROID_HOME") or os.environ.get("ANDROID_SDK_ROOT")
    sdk_present = bool(android_home and pathlib.Path(android_home).exists())
    sdk_ev = {"android_home": android_home} if sdk_present else None

    adb = shutil.which("adb")
    if not adb and android_home:
        cand = pathlib.Path(android_home) / "platform-tools" / ("adb.exe" if platform.system() == "Windows" else "adb")
        if cand.exists():
            adb = str(cand)

    emulator = shutil.which("emulator")
    if not emulator and android_home:
        cand = pathlib.Path(android_home) / "emulator" / ("emulator.exe" if platform.system() == "Windows" else "emulator")
        if cand.exists():
            emulator = str(cand)

    return [
        _presence_capability("android:sdk-present", sdk_present, sdk_ev, installed=sdk_present),
        _presence_capability("android:emulator-present", emulator is not None, emulator, installed=emulator is not None),
    ]


def _macos_simctl_capabilities() -> list[dict[str, Any]]:
    """Passive observation of CoreSimulator runtimes without spawning VMs."""
    xcrun = shutil.which("xcrun")
    if not xcrun:
        return [_presence_capability("macos:simctl-runtimes", False)]
    raw = _run_text([xcrun, "simctl", "list", "runtimes", "-j"], timeout=6)
    if not raw:
        return [_presence_capability("macos:simctl-runtimes", False)]
    try:
        data = json.loads(raw)
        runtimes = [r.get("name") or r.get("identifier") for r in data.get("runtimes", [])]
        return [_presence_capability("macos:simctl-runtimes", len(runtimes) > 0, {"runtimes": runtimes}, installed=True)]
    except json.JSONDecodeError:
        return [_presence_capability("macos:simctl-runtimes", True, "simctl present", installed=True)]


def _macos_metal_capability() -> dict[str, Any]:
    """Passive observation of Metal GPU compute device."""
    metal_fw = (pathlib.Path("/System/Library/Frameworks") / "Metal.framework").exists()
    if not metal_fw:
        return _presence_capability("macos:metal-gpu-device", False)
    gpu_info = _run_text(["system_profiler", "SPDisplaysDataType"], timeout=6)
    evidence: dict[str, str] = {}
    if gpu_info:
        for line in gpu_info.splitlines():
            line_str = line.strip()
            if any(k in line_str for k in ("Chipset Model:", "Metal Support:", "Metal Family:")):
                parts = line_str.split(":", 1)
                if len(parts) == 2:
                    evidence[parts[0].strip()] = parts[1].strip()
    return _presence_capability(
        "macos:metal-gpu-device", True, evidence or "Metal.framework present", installed=True
    )


def _cpu_features(system: str) -> list[str]:
    """Extract key hardware vector/acceleration instruction set extensions."""
    features: list[str] = []
    if system == "Linux":
        path = pathlib.Path("/proc/cpuinfo")
        if path.exists():
            for line in path.read_text(errors="replace").splitlines():
                if line.startswith("flags") or line.startswith("Features"):
                    parts = line.split(":", 1)
                    if len(parts) > 1:
                        all_flags = set(parts[1].split())
                        interesting = {
                            "avx", "avx2", "avx512f", "avx512bw", "avx512vl",
                            "amx_tile", "aes", "neon", "asimd", "fp", "fphp", "asimdhp",
                        }
                        features = sorted(list(all_flags & interesting))
                        break
    elif system == "Darwin":
        raw = _run_text(["sysctl", "-n", "machdep.cpu.features", "machdep.cpu.leaf7_features"])
        if raw:
            all_flags = set(raw.lower().split())
            interesting = {"avx", "avx2", "avx512f", "aes", "neon", "arm64"}
            features = sorted(list(all_flags & interesting))
    return features


def _steal_ticks(system: str) -> float | None:
    """Read hypervisor CPU steal ticks on Linux."""
    if system == "Linux":
        path = pathlib.Path("/proc/stat")
        if path.exists():
            for line in path.read_text(errors="replace").splitlines():
                if line.startswith("cpu "):
                    parts = line.split()
                    if len(parts) >= 9:
                        try:
                            return float(parts[8])
                        except ValueError:
                            pass
    return None


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
        "adb", "emulator", "rustc", "cargo", "go", "node", "python3",
    ):
        path = shutil.which(command)
        capabilities.append(_presence_capability(f"command:{command}", path is not None, path))

    # Probe Docker daemon responsiveness
    capabilities.append(_docker_daemon_capability())

    # Probe Android SDK environment
    capabilities.extend(_android_capabilities())

    if system == "Linux":
        for device in ("/dev/kvm", "/dev/dri", "/dev/fuse", "/dev/net/tun"):
            p = pathlib.Path(device)
            capabilities.append(_presence_capability(f"device:{device}", p.exists(), str(p) if p.exists() else None,
                                                     installed=None))
        capabilities.append(_linux_dev_shm_capability())
        capabilities.extend(_linux_kvm_access_capabilities())
        cgroup_v2 = pathlib.Path("/sys/fs/cgroup/cgroup.controllers").exists()
        capabilities.append(_presence_capability("linux:cgroup-v2", cgroup_v2,
                                                 "/sys/fs/cgroup/cgroup.controllers" if cgroup_v2 else None,
                                                 installed=None))
        binfmt = pathlib.Path("/proc/sys/fs/binfmt_misc").exists()
        capabilities.append(_presence_capability("linux:binfmt-misc", binfmt,
                                                 "/proc/sys/fs/binfmt_misc" if binfmt else None,
                                                 installed=None))
    elif system == "Windows":
        capabilities.extend(_windows_hyperv_capabilities())
        capabilities.extend(_windows_additional_capabilities())
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
        capabilities.extend(_macos_simctl_capabilities())
        capabilities.append(_macos_metal_capability())

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
                "features": _cpu_features(system),
                "steal_ticks": _steal_ticks(system),
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
