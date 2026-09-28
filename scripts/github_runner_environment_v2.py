#!/usr/bin/env python3
"""Cross-platform V2 census for standard public GitHub-hosted runners.

This augments github-runner-capability/v1 without creating a new schema.
It intentionally records public-safe capability/resource semantics rather than
dumping environment variables or unique host identifiers.
"""
from __future__ import annotations

import argparse
import json
import os
import pathlib
import platform
import shutil
import socket
import stat
import subprocess
import sys
import tempfile
from typing import Any

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
import github_runner_census as passive

PROBE_VERSION = "public-environment-v2/1"


def _run(argv: list[str], timeout: int = 10) -> tuple[int | None, str, str]:
    try:
        cp = subprocess.run(
            argv, check=False, capture_output=True, text=True, timeout=timeout
        )
        return cp.returncode, cp.stdout.strip(), cp.stderr.strip()
    except (OSError, subprocess.SubprocessError) as exc:
        return None, "", f"{type(exc).__name__}: {exc}"


def _obs(name: str, value: Any, unit: str | None = None,
         note: str | None = None) -> dict[str, Any]:
    return {"name": name, "value": value, "unit": unit, "note": note}


def _cap(name: str, *, observed: bool | None, installed: bool | None,
         callable_: bool | None, exercised: bool, oracle: bool,
         classification: str, reason: str, evidence: Any = None) -> dict[str, Any]:
    return {
        "name": name,
        "advertised": None,
        "observed": observed,
        "installed": installed,
        "callable": callable_,
        "exercised": exercised,
        "oracleSatisfied": oracle,
        "classification": classification,
        "reason": reason,
        "evidence": evidence,
    }


def _command_capability(command: str, args: list[str] | None = None) -> dict[str, Any]:
    exe = shutil.which(command)
    if not exe:
        return _cap(
            f"command:{command}", observed=False, installed=False, callable_=False,
            exercised=False, oracle=False, classification="NEGATIVE_OBSERVATION",
            reason=f"{command} is not installed",
        )
    evidence: dict[str, Any] = {"path_basename": pathlib.Path(exe).name}
    if args is None:
        return _cap(
            f"command:{command}", observed=True, installed=True, callable_=None,
            exercised=False, oracle=False, classification="INCONCLUSIVE",
            reason=f"{command} is installed; not exercised by this passive probe",
            evidence=evidence,
        )
    code, out, err = _run([exe, *args], timeout=15)
    evidence.update({
        "exit_code": code,
        "stdout": out[:1000] or None,
        "stderr": err[:500] or None,
    })
    ok = code == 0
    return _cap(
        f"command:{command}", observed=True, installed=True, callable_=ok,
        exercised=True, oracle=ok,
        classification="SUPPORTED" if ok else "ORACLE_FAILURE",
        reason=f"{command} bounded query succeeded" if ok
               else f"{command} exists but bounded query failed",
        evidence=evidence,
    )


def _loopback_family(family: int, host: str) -> dict[str, Any]:
    label = "ipv6" if family == socket.AF_INET6 else "ipv4"
    server = socket.socket(family, socket.SOCK_STREAM)
    client = socket.socket(family, socket.SOCK_STREAM)
    try:
        server.settimeout(2)
        client.settimeout(2)
        server.bind((host, 0))
        server.listen(1)
        port = server.getsockname()[1]
        client.connect((host, port))
        conn, _ = server.accept()
        try:
            client.sendall(b"runner-census-v2")
            got = conn.recv(64)
        finally:
            conn.close()
        ok = got == b"runner-census-v2"
        return _cap(
            f"network:loopback-{label}", observed=True, installed=None,
            callable_=True, exercised=True, oracle=ok,
            classification="SUPPORTED" if ok else "ORACLE_FAILURE",
            reason=f"{label} loopback bind/connect nonce succeeded" if ok
                   else f"{label} loopback nonce mismatch",
            evidence={"family": label},
        )
    except OSError as exc:
        return _cap(
            f"network:loopback-{label}", observed=False, installed=None,
            callable_=False, exercised=True, oracle=False,
            classification="NEGATIVE_OBSERVATION",
            reason=f"{label} loopback bind/connect unavailable",
            evidence={"error_type": type(exc).__name__, "errno": exc.errno},
        )
    finally:
        client.close()
        server.close()


def _network_interface_counts() -> dict[str, int]:
    counts = {"interfaces": 0, "ipv4_bind_candidates": 0, "ipv6_bind_candidates": 0}
    try:
        counts["interfaces"] = len(socket.if_nameindex())
    except (OSError, AttributeError):
        pass

    # Do not publish addresses. getaddrinfo on hostname is enough to characterize
    # address-family exposure without enumerating unique interface identifiers.
    try:
        infos = socket.getaddrinfo(socket.gethostname(), None, 0, socket.SOCK_STREAM)
    except OSError:
        infos = []
    for family, *_rest in infos:
        if family == socket.AF_INET:
            counts["ipv4_bind_candidates"] += 1
        elif family == socket.AF_INET6:
            counts["ipv6_bind_candidates"] += 1
    return counts


def _filesystem_semantics() -> dict[str, Any]:
    root = pathlib.Path(os.environ.get("RUNNER_TEMP") or tempfile.gettempdir())
    with tempfile.TemporaryDirectory(prefix="runner-census-v2-", dir=str(root)) as td:
        d = pathlib.Path(td)
        mixed = d / "CaseProbe"
        mixed.write_text("nonce", encoding="utf-8")
        case_insensitive = (d / "caseprobe").exists()

        symlink_ok = False
        symlink_error = None
        try:
            (d / "symlink").symlink_to(mixed)
            symlink_ok = (d / "symlink").read_text(encoding="utf-8") == "nonce"
        except OSError as exc:
            symlink_error = type(exc).__name__

        hardlink_ok = False
        hardlink_error = None
        try:
            os.link(mixed, d / "hardlink")
            hardlink_ok = (d / "hardlink").read_text(encoding="utf-8") == "nonce"
        except OSError as exc:
            hardlink_error = type(exc).__name__

        executable_bit = None
        if os.name != "nt":
            probe = d / "exec-probe"
            probe.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
            probe.chmod(probe.stat().st_mode | stat.S_IXUSR)
            executable_bit = os.access(probe, os.X_OK)

        return {
            "case_insensitive": case_insensitive,
            "symlink_create_and_read": symlink_ok,
            "symlink_error_type": symlink_error,
            "hardlink_create_and_read": hardlink_ok,
            "hardlink_error_type": hardlink_error,
            "executable_bit_semantics": executable_bit,
        }


def _linux_details() -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    observations: list[dict[str, Any]] = []
    capabilities: list[dict[str, Any]] = []

    os_release: dict[str, str] = {}
    p = pathlib.Path("/etc/os-release")
    if p.exists():
        for line in p.read_text(errors="replace").splitlines():
            if "=" not in line:
                continue
            key, value = line.split("=", 1)
            if key in {"ID", "VERSION_ID", "VERSION_CODENAME", "PRETTY_NAME"}:
                os_release[key] = value.strip().strip('"')
    observations.append(_obs("linux:os-release", os_release))

    code, out, _ = _run(["lscpu", "-J"], timeout=10)
    if code == 0:
        try:
            raw = json.loads(out)
            allow = {
                "Architecture", "CPU(s)", "Thread(s) per core", "Core(s) per socket",
                "Socket(s)", "Vendor ID", "Model name", "Virtualization",
                "Hypervisor vendor", "L1d cache", "L1i cache", "L2 cache", "L3 cache",
            }
            values = {
                row.get("field", "").rstrip(":"): row.get("data")
                for row in raw.get("lscpu", [])
                if row.get("field", "").rstrip(":") in allow
            }
            observations.append(_obs("linux:lscpu-selected", values))
        except json.JSONDecodeError:
            pass

    meminfo: dict[str, int] = {}
    mp = pathlib.Path("/proc/meminfo")
    if mp.exists():
        for line in mp.read_text(errors="replace").splitlines():
            if ":" not in line:
                continue
            key, rest = line.split(":", 1)
            if key not in {"MemTotal", "MemAvailable", "SwapTotal", "SwapFree"}:
                continue
            parts = rest.strip().split()
            if parts and parts[0].isdigit():
                meminfo[key] = int(parts[0]) * 1024
    observations.append(_obs("linux:memory-selected", meminfo))

    pid1 = pathlib.Path("/proc/1/comm")
    observations.append(_obs(
        "linux:pid1",
        pid1.read_text(errors="replace").strip() if pid1.exists() else None,
    ))

    sudo = shutil.which("sudo")
    if sudo:
        code, _out, err = _run([sudo, "-n", "true"], timeout=5)
        capabilities.append(_cap(
            "linux:passwordless-sudo", observed=True, installed=True,
            callable_=code == 0, exercised=True, oracle=code == 0,
            classification="SUPPORTED" if code == 0 else "NEGATIVE_OBSERVATION",
            reason="sudo -n true succeeded" if code == 0
                   else "sudo exists but noninteractive elevation failed",
            evidence={"exit_code": code, "stderr": err[:300] or None},
        ))

    docker = shutil.which("docker")
    if docker:
        code, out, err = _run(
            [docker, "info", "--format", "{{json .ServerVersion}}"], timeout=10
        )
        capabilities.append(_cap(
            "container:docker-daemon-query", observed=True, installed=True,
            callable_=code == 0, exercised=True, oracle=code == 0,
            classification="SUPPORTED" if code == 0 else "NEGATIVE_OBSERVATION",
            reason="Docker daemon query succeeded" if code == 0
                   else "Docker CLI present but local daemon query failed",
            evidence={"exit_code": code, "server_version": out or None,
                      "stderr": err[:300] or None},
        ))

    kvm = pathlib.Path("/dev/kvm")
    capabilities.append(_cap(
        "linux:kvm-device-access",
        observed=kvm.exists(), installed=None,
        callable_=os.access(kvm, os.R_OK | os.W_OK) if kvm.exists() else False,
        exercised=False, oracle=False,
        classification="INCONCLUSIVE" if kvm.exists() else "NEGATIVE_OBSERVATION",
        reason="/dev/kvm observed; active VCPU oracle belongs to primitive qualification"
               if kvm.exists() else "/dev/kvm not observed",
        evidence={"read_write_access": os.access(kvm, os.R_OK | os.W_OK) if kvm.exists() else False},
    ))

    observations.append(_obs("linux:container-context", {
        "dockerenv": pathlib.Path("/.dockerenv").exists(),
        "cgroup_v2": pathlib.Path("/sys/fs/cgroup/cgroup.controllers").exists(),
        "binfmt_misc": pathlib.Path("/proc/sys/fs/binfmt_misc").exists(),
    }))
    return observations, capabilities


def _darwin_details() -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    observations: list[dict[str, Any]] = []
    capabilities: list[dict[str, Any]] = []

    sw: dict[str, str] = {}
    code, out, _ = _run(["sw_vers"], timeout=10)
    if code == 0:
        for line in out.splitlines():
            if ":" in line:
                key, value = line.split(":", 1)
                sw[key.strip()] = value.strip()
    observations.append(_obs("macos:sw-vers", sw))

    sysctls: dict[str, str] = {}
    for key in (
        "hw.ncpu", "hw.physicalcpu", "hw.logicalcpu", "hw.memsize",
        "kern.hv_support", "hw.optional.arm64",
    ):
        code, out, _ = _run(["sysctl", "-n", key], timeout=5)
        if code == 0:
            sysctls[key] = out
    observations.append(_obs("macos:selected-sysctl", sysctls))

    sudo = shutil.which("sudo")
    if sudo:
        code, _out, err = _run([sudo, "-n", "true"], timeout=5)
        capabilities.append(_cap(
            "macos:passwordless-sudo", observed=True, installed=True,
            callable_=code == 0, exercised=True, oracle=code == 0,
            classification="SUPPORTED" if code == 0 else "NEGATIVE_OBSERVATION",
            reason="sudo -n true succeeded" if code == 0
                   else "sudo exists but noninteractive elevation failed",
            evidence={"exit_code": code, "stderr": err[:300] or None},
        ))

    hv = pathlib.Path("/System/Library/Frameworks/Hypervisor.framework").exists()
    hv_support = sysctls.get("kern.hv_support")
    capabilities.append(_cap(
        "macos:hypervisor-framework-surface", observed=hv, installed=hv,
        callable_=hv_support == "1" if hv_support is not None else None,
        exercised=False, oracle=False,
        classification="INCONCLUSIVE" if hv else "NEGATIVE_OBSERVATION",
        reason="Hypervisor.framework observed; no nested-guest oracle executed"
               if hv else "Hypervisor.framework not observed",
        evidence={"kern_hv_support": hv_support},
    ))

    observations.append(_obs("macos:rosetta", {
        "installed": pathlib.Path("/Library/Apple/usr/share/rosetta/rosetta").exists(),
    }))

    for command, args in (
        ("xcodebuild", ["-version"]),
        ("xcrun", ["--version"]),
        ("cups-config", ["--version"]),
        ("lpstat", ["-r"]),
    ):
        capabilities.append(_command_capability(command, args))
    return observations, capabilities


def _powershell() -> str | None:
    return shutil.which("pwsh") or shutil.which("powershell") or shutil.which("powershell.exe")


def _ps_json(script: str, timeout: int = 20) -> Any:
    ps = _powershell()
    if not ps:
        return None
    code, out, _ = _run([
        ps, "-NoLogo", "-NoProfile", "-NonInteractive", "-Command",
        f"$ErrorActionPreference='Stop'; {script} | ConvertTo-Json -Depth 6 -Compress"
    ], timeout=timeout)
    if code != 0 or not out:
        return None
    try:
        return json.loads(out)
    except json.JSONDecodeError:
        return None


def _windows_details() -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    observations: list[dict[str, Any]] = []
    capabilities: list[dict[str, Any]] = []

    os_info = _ps_json(
        "$os=Get-CimInstance Win32_OperatingSystem; "
        "$cs=Get-CimInstance Win32_ComputerSystem; "
        "$cpu=Get-CimInstance Win32_Processor | Select-Object -First 1; "
        "[ordered]@{"
        "caption=$os.Caption;version=$os.Version;build=$os.BuildNumber;"
        "architecture=$os.OSArchitecture;"
        "total_visible_memory_kib=$os.TotalVisibleMemorySize;"
        "free_physical_memory_kib=$os.FreePhysicalMemory;"
        "total_virtual_memory_kib=$os.TotalVirtualMemorySize;"
        "free_virtual_memory_kib=$os.FreeVirtualMemory;"
        "logical_processors=$cs.NumberOfLogicalProcessors;"
        "processors=$cs.NumberOfProcessors;total_physical_memory=$cs.TotalPhysicalMemory;"
        "cpu_name=$cpu.Name;cpu_cores=$cpu.NumberOfCores;"
        "cpu_logical=$cpu.NumberOfLogicalProcessors;"
        "virtualization_firmware=$cpu.VirtualizationFirmwareEnabled;"
        "slat=$cpu.SecondLevelAddressTranslationExtensions}"
    )
    observations.append(_obs("windows:selected-system", os_info))

    admin = _ps_json(
        "$p=[Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent();"
        "$p.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)"
    )
    capabilities.append(_cap(
        "windows:administrator-context",
        observed=bool(admin), installed=None, callable_=bool(admin),
        exercised=True, oracle=bool(admin),
        classification="SUPPORTED" if admin else "NEGATIVE_OBSERVATION",
        reason="runner process is in Administrators" if admin
               else "runner process is not in Administrators",
    ))

    services = _ps_json(
        "$names='Spooler','docker','vmcompute','hns';"
        "$rows=@(); foreach($n in $names){$s=Get-Service $n -ErrorAction SilentlyContinue;"
        "$rows += [ordered]@{name=$n;present=[bool]$s;status=if($s){$s.Status.ToString()}else{$null}}};"
        "$rows"
    )
    observations.append(_obs("windows:selected-services", services))

    features = _ps_json(
        "$names='Microsoft-Windows-Subsystem-Linux','VirtualMachinePlatform','Microsoft-Hyper-V-All';"
        "$rows=@(); foreach($n in $names){try{$f=Get-WindowsOptionalFeature -Online -FeatureName $n -ErrorAction Stop;"
        "$rows += [ordered]@{name=$n;state=$f.State.ToString()}}catch{$rows += [ordered]@{name=$n;state='query-failed'}}};"
        "$rows"
    )
    observations.append(_obs("windows:selected-optional-features", features))

    wsl = shutil.which("wsl") or shutil.which("wsl.exe")
    if wsl:
        code, out, err = _run([wsl, "--status"], timeout=15)
        capabilities.append(_cap(
            "windows:wsl-status", observed=True, installed=True,
            callable_=code == 0, exercised=True, oracle=code == 0,
            classification="SUPPORTED" if code == 0 else "INCONCLUSIVE",
            reason="wsl --status succeeded" if code == 0
                   else "WSL command exists but status query did not succeed",
            evidence={"exit_code": code, "stdout": out[:800] or None,
                      "stderr": err[:500] or None},
        ))

    docker = shutil.which("docker") or shutil.which("docker.exe")
    if docker:
        code, out, err = _run([docker, "version", "--format", "{{json .Server.Version}}"], timeout=15)
        capabilities.append(_cap(
            "container:docker-daemon-query", observed=True, installed=True,
            callable_=code == 0, exercised=True, oracle=code == 0,
            classification="SUPPORTED" if code == 0 else "NEGATIVE_OBSERVATION",
            reason="Windows Docker daemon query succeeded" if code == 0
                   else "Docker CLI present but daemon query failed",
            evidence={"exit_code": code, "server_version": out or None,
                      "stderr": err[:500] or None},
        ))

    print_surface = _ps_json(
        "$cmds='Add-Printer','Get-Printer','Out-Printer';"
        "$rows=@(); foreach($c in $cmds){$x=Get-Command $c -ErrorAction SilentlyContinue;"
        "$rows += [ordered]@{name=$c;present=[bool]$x;"
        "parameters=if($x){@($x.Parameters.Keys | Sort-Object)}else{@()}}};$rows"
    )
    observations.append(_obs("windows:print-command-surface", print_surface))

    vswhere = pathlib.Path(os.environ.get("ProgramFiles(x86)", r"C:\Program Files (x86)")) / \
        "Microsoft Visual Studio" / "Installer" / "vswhere.exe"
    if vswhere.exists():
        code, out, err = _run([
            str(vswhere), "-latest", "-products", "*",
            "-requires", "Microsoft.Component.MSBuild",
            "-find", r"MSBuild\**\Bin\MSBuild.exe",
        ], timeout=15)
        capabilities.append(_cap(
            "windows:msbuild-vswhere-discovery", observed=True, installed=True,
            callable_=code == 0 and bool(out), exercised=True,
            oracle=code == 0 and bool(out),
            classification="SUPPORTED" if code == 0 and bool(out) else "INCONCLUSIVE",
            reason="vswhere found MSBuild" if code == 0 and bool(out)
                   else "vswhere exists but MSBuild was not resolved",
            evidence={"found_count": len([x for x in out.splitlines() if x.strip()]),
                      "stderr": err[:300] or None},
        ))
    return observations, capabilities


def _service_container_probe() -> dict[str, Any] | None:
    host = os.environ.get("CENSUS_SERVICE_HOST")
    port_raw = os.environ.get("CENSUS_SERVICE_PORT")
    if not host or not port_raw:
        return None
    try:
        port = int(port_raw)
    except ValueError:
        return _cap(
            "actions:service-container-connectivity", observed=None, installed=None,
            callable_=False, exercised=False, oracle=False,
            classification="HARNESS_FAILURE", reason="invalid service-container port",
        )
    try:
        with socket.create_connection((host, port), timeout=3) as s:
            s.sendall(b"*1\r\n$4\r\nPING\r\n")
            got = s.recv(128)
        ok = got.startswith(b"+PONG")
        return _cap(
            "actions:service-container-connectivity", observed=True, installed=None,
            callable_=True, exercised=True, oracle=ok,
            classification="SUPPORTED" if ok else "ORACLE_FAILURE",
            reason="service-container DNS/TCP/Redis PING oracle succeeded" if ok
                   else "service-container connected but Redis PING oracle failed",
            evidence={"service": "redis", "port": port},
        )
    except OSError as exc:
        return _cap(
            "actions:service-container-connectivity", observed=False, installed=None,
            callable_=False, exercised=True, oracle=False,
            classification="NEGATIVE_OBSERVATION",
            reason="service-container endpoint was not reachable",
            evidence={"error_type": type(exc).__name__, "errno": exc.errno},
        )


def build_receipt(label: str | None = None) -> dict[str, Any]:
    receipt = passive.build_receipt(label)
    receipt["provenance"]["probe_version"] = PROBE_VERSION
    receipt["environment"]["execution_model"] = os.environ.get(
        "CENSUS_EXECUTION_MODEL", "native-host"
    )
    receipt["environment"]["parent_runner_label"] = os.environ.get(
        "CENSUS_PARENT_RUNNER_LABEL"
    )
    receipt["environment"]["container_image"] = os.environ.get("CENSUS_CONTAINER_IMAGE")
    receipt["environment"]["service_container"] = os.environ.get("CENSUS_SERVICE_CONTAINER")

    receipt["observations"].extend([
        _obs("common:network-family-counts", _network_interface_counts()),
        _obs("common:filesystem-semantics", _filesystem_semantics()),
        _obs("common:python", {
            "version": platform.python_version(),
            "implementation": platform.python_implementation(),
        }),
    ])
    receipt["capabilities"].extend([
        _loopback_family(socket.AF_INET, "127.0.0.1"),
        _loopback_family(socket.AF_INET6, "::1"),
    ])

    common_commands: list[tuple[str, list[str] | None]] = [
        ("git", ["--version"]),
        ("python", ["--version"]),
        ("python3", ["--version"]),
        ("node", ["--version"]),
        ("dotnet", ["--version"]),
        ("java", ["-version"]),
        ("go", ["version"]),
        ("rustc", ["--version"]),
        ("cargo", ["--version"]),
        ("cmake", ["--version"]),
        ("ninja", ["--version"]),
        ("clang", ["--version"]),
        ("gcc", ["--version"]),
        ("docker", None),
        ("podman", None),
        ("qemu-system-x86_64", None),
        ("qemu-system-aarch64", None),
    ]
    receipt["capabilities"].extend(
        _command_capability(command, args) for command, args in common_commands
    )

    system = platform.system()
    if system == "Linux":
        observations, capabilities = _linux_details()
    elif system == "Darwin":
        observations, capabilities = _darwin_details()
    elif system == "Windows":
        observations, capabilities = _windows_details()
    else:
        observations = [_obs("platform:unhandled-system", system)]
        capabilities = []

    receipt["observations"].extend(observations)
    receipt["capabilities"].extend(capabilities)

    service = _service_container_probe()
    if service is not None:
        receipt["capabilities"].append(service)

    receipt["warnings"].extend([
        "V2 refresh values describe the observed job/image, not provider guarantees",
        "native-host, shared-container, job-container, service-container, VM-guest, and emulator evidence must remain distinct",
        "query success is not promoted beyond the named oracle",
        "addresses, environment dumps, serials, and unique hardware identifiers are intentionally not collected",
    ])
    return receipt


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--label")
    parser.add_argument("--out", required=True)
    args = parser.parse_args()
    receipt = build_receipt(args.label)
    path = pathlib.Path(args.out)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(receipt, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(f"ENVIRONMENT_V2_RECEIPT={path}")
    print(json.dumps(receipt, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
