#!/usr/bin/env python3
"""Qualify native/system container substrates with resource/device/network evidence.

The script is intentionally self-contained and public-safe.  It treats lifecycle,
resource visibility, callability, and exercised oracles as separate evidence.
"""
from __future__ import annotations

import argparse
import json
import os
import pathlib
import platform
import shutil
import subprocess
import tempfile
import time
import uuid

VERSION = "container-substrate/0.2"


def run(argv, timeout=60, cwd=None, env=None):
    try:
        cp = subprocess.run(
            argv,
            cwd=cwd,
            env=env,
            text=True,
            capture_output=True,
            timeout=timeout,
            check=False,
        )
        return {
            "argv": [str(x) for x in argv],
            "exit_code": cp.returncode,
            "stdout": cp.stdout[-12000:],
            "stderr": cp.stderr[-12000:],
        }
    except Exception as exc:
        return {
            "argv": [str(x) for x in argv],
            "exit_code": None,
            "stdout": "",
            "stderr": f"{type(exc).__name__}: {exc}",
        }


def sh(command, timeout=60):
    if os.name == "nt":
        return run(["powershell", "-NoProfile", "-NonInteractive", "-Command", command], timeout=timeout)
    return run(["sh", "-lc", command], timeout=timeout)


def ok(result):
    return result.get("exit_code") == 0


def command(name):
    return shutil.which(name)


def read_text(path, limit=20000):
    try:
        return pathlib.Path(path).read_text(errors="replace")[:limit]
    except Exception:
        return None


def parse_json_stdout(result):
    if not ok(result) or not result.get("stdout"):
        return None
    try:
        return json.loads(result["stdout"])
    except json.JSONDecodeError:
        return None


def parse_sections(text):
    """Parse ===NAME=== delimited probe output without losing raw evidence."""
    sections = {}
    current = None
    for line in (text or "").splitlines():
        if line.startswith("===") and line.endswith("===") and len(line) > 6:
            current = line[3:-3]
            sections.setdefault(current, [])
            continue
        if current is not None:
            sections[current].append(line)
    return {name: "\n".join(lines).strip() for name, lines in sections.items()}


def host_census():
    data = {
        "system": platform.system(),
        "release": platform.release(),
        "version": platform.version(),
        "machine": platform.machine(),
        "processor": platform.processor(),
        "logical_cpus": os.cpu_count(),
        "github_actions": os.environ.get("GITHUB_ACTIONS") == "true",
        "runner_name": os.environ.get("RUNNER_NAME"),
        "runner_os": os.environ.get("RUNNER_OS"),
        "runner_arch": os.environ.get("RUNNER_ARCH"),
        "requested_label": os.environ.get("CENSUS_REQUESTED_LABEL"),
    }

    if platform.system() == "Linux":
        data["kernel"] = run(["uname", "-a"])
        data["meminfo"] = read_text("/proc/meminfo")
        data["self_status"] = read_text("/proc/self/status")
        data["cgroup"] = read_text("/proc/self/cgroup")
        data["mounts"] = run(["findmnt", "-J"]) if command("findmnt") else None
        data["network"] = run(["ip", "-j", "address"]) if command("ip") else None
        data["routes"] = run(["ip", "-j", "route"]) if command("ip") else None
        data["pci"] = run(["lspci", "-nn"]) if command("lspci") else None
        data["usb"] = run(["lsusb"]) if command("lsusb") else None
        data["accelerators"] = {}
        for tool, argv in (
            ("nvidia-smi", ["nvidia-smi", "-L"]),
            ("rocminfo", ["rocminfo"]),
            ("clinfo", ["clinfo", "-l"]),
        ):
            if command(tool):
                data["accelerators"][tool] = run(argv, timeout=20)
        devs = [
            "/dev/kvm", "/dev/dri", "/dev/nvidia0", "/dev/nvidiactl",
            "/dev/infiniband", "/dev/bus/usb", "/dev/net/tun", "/dev/fuse",
            "/dev/tpm0", "/dev/tpmrm0",
        ]
        data["device_paths"] = {
            p: {
                "exists": pathlib.Path(p).exists(),
                "listing": run(["ls", "-ld", p]) if pathlib.Path(p).exists() else None,
            }
            for p in devs
        }
    elif platform.system() == "Darwin":
        data["hardware"] = run(["system_profiler", "SPHardwareDataType", "-json"], timeout=30)
        data["display"] = run(["system_profiler", "SPDisplaysDataType", "-json"], timeout=30)
        data["network"] = run(["ifconfig", "-a"])
        data["routes"] = run(["netstat", "-rn"])
        data["vm_stat"] = run(["vm_stat"])
        data["sysctl"] = {
            "logicalcpu": run(["sysctl", "-n", "hw.logicalcpu"]),
            "memsize": run(["sysctl", "-n", "hw.memsize"]),
            "hv_support": run(["sysctl", "-n", "kern.hv_support"]),
        }
    elif platform.system() == "Windows":
        ps = r"""
$ErrorActionPreference='SilentlyContinue'
function NetSnapshot {
  @(
    Get-NetIPConfiguration | ForEach-Object {
      [ordered]@{
        interfaceAlias = $_.InterfaceAlias
        interfaceDescription = $_.InterfaceDescription
        ipv4 = @($_.IPv4Address | ForEach-Object { $_.IPAddress })
        ipv6 = @($_.IPv6Address | ForEach-Object { $_.IPAddress })
        gateways = @($_.IPv4DefaultGateway | ForEach-Object { $_.NextHop })
        dns = @($_.DNSServer.ServerAddresses)
      }
    }
  )
}
[ordered]@{
  computer = Get-CimInstance Win32_ComputerSystem | Select-Object Name,Manufacturer,Model,NumberOfLogicalProcessors,TotalPhysicalMemory
  os = Get-CimInstance Win32_OperatingSystem | Select-Object Caption,Version,BuildNumber,OSArchitecture,FreePhysicalMemory,TotalVisibleMemorySize
  cpu = @(Get-CimInstance Win32_Processor | Select-Object Name,Manufacturer,NumberOfCores,NumberOfLogicalProcessors,VirtualizationFirmwareEnabled)
  display = @(Get-CimInstance Win32_VideoController | Select-Object Name,AdapterCompatibility,DriverVersion,VideoProcessor)
  net = @(Get-NetAdapter | Select-Object Name,InterfaceDescription,Status,LinkSpeed,MacAddress)
  ip = @(NetSnapshot)
  disks = @(Get-Volume | Select-Object DriveLetter,FileSystem,Size,SizeRemaining)
  hyperv = Get-WindowsOptionalFeature -Online -FeatureName Microsoft-Hyper-V-All | Select-Object FeatureName,State
  containers = Get-WindowsFeature Containers | Select-Object Name,InstallState
} | ConvertTo-Json -Depth 5 -Compress
"""
        windows_result = run(["powershell", "-NoProfile", "-NonInteractive", "-Command", ps], timeout=45)
        data["windows"] = {
            "command": windows_result,
            "parsed": parse_json_stdout(windows_result),
        }
        docker_result = run(["docker", "version", "--format", "{{json .}}"], timeout=30) if command("docker") else None
        data["docker"] = {
            "command": docker_result,
            "parsed": parse_json_stdout(docker_result) if docker_result else None,
        }
    return data


LINUX_INNER = r"""set -eu
echo '===UNAME==='
uname -a || true
echo '===CPU==='
getconf _NPROCESSORS_ONLN 2>/dev/null || nproc 2>/dev/null || true
echo '===MEMINFO==='
cat /proc/meminfo 2>/dev/null || true
echo '===STATUS==='
cat /proc/self/status 2>/dev/null || true
echo '===CGROUP==='
cat /proc/self/cgroup 2>/dev/null || true
echo '===MOUNTS==='
cat /proc/mounts 2>/dev/null || true
echo '===NETWORK==='
if command -v ip >/dev/null 2>&1; then
  ip -details addr 2>/dev/null || true
elif command -v ifconfig >/dev/null 2>&1; then
  ifconfig -a 2>/dev/null || true
else
  cat /proc/net/dev 2>/dev/null || true
fi
echo '===ROUTES==='
if command -v ip >/dev/null 2>&1; then
  ip route 2>/dev/null || true
elif command -v route >/dev/null 2>&1; then
  route -n 2>/dev/null || true
else
  cat /proc/net/route 2>/dev/null || true
fi
echo '===DNS==='
cat /etc/resolv.conf 2>/dev/null || true
echo '===DNS_ORACLE==='
if command -v nslookup >/dev/null 2>&1; then
  nslookup github.com 2>&1 || true
elif command -v getent >/dev/null 2>&1; then
  getent hosts github.com 2>&1 || true
else
  echo 'UNKNOWN no DNS query tool'
fi
echo '===HTTPS_EGRESS==='
if command -v wget >/dev/null 2>&1; then
  if wget -q -T 10 -O /dev/null https://github.com/ 2>/dev/null; then echo PASS; else echo FAIL; fi
elif command -v curl >/dev/null 2>&1; then
  if curl -fsS --max-time 10 -o /dev/null https://github.com/; then echo PASS; else echo FAIL; fi
else
  echo 'UNKNOWN no HTTPS client'
fi
echo '===DEVICES==='
for p in /dev/kvm /dev/dri /dev/nvidia0 /dev/nvidiactl /dev/infiniband /dev/bus/usb /dev/net/tun /dev/fuse /dev/tpm0 /dev/tpmrm0; do
  if [ -e "$p" ]; then
    ls -ld "$p" 2>/dev/null || true
    if [ -d "$p" ]; then find "$p" -maxdepth 2 -mindepth 1 -print 2>/dev/null | head -100 || true; fi
  else
    echo "MISSING $p"
  fi
done
echo '===FILESYSTEM==='
(df -T 2>/dev/null || df -h 2>/dev/null || true)
echo '===IDENTITY==='
(id || true)
"""


def windows_probe_script():
    return r"""$ErrorActionPreference='SilentlyContinue'
$dns = @()
try { $dns = @([System.Net.Dns]::GetHostAddresses('github.com') | ForEach-Object { $_.IPAddressToString }) } catch {}
$https = $false
try {
  $request = [System.Net.HttpWebRequest]::Create('https://github.com/')
  $request.Method = 'HEAD'
  $request.Timeout = 10000
  $response = $request.GetResponse()
  $https = $true
  $response.Close()
} catch {}
$ip = @(
  Get-NetIPConfiguration | ForEach-Object {
    [ordered]@{
      interfaceAlias = $_.InterfaceAlias
      interfaceDescription = $_.InterfaceDescription
      ipv4 = @($_.IPv4Address | ForEach-Object { $_.IPAddress })
      ipv6 = @($_.IPv6Address | ForEach-Object { $_.IPAddress })
      gateways = @($_.IPv4DefaultGateway | ForEach-Object { $_.NextHop })
      dns = @($_.DNSServer.ServerAddresses)
    }
  }
)
[ordered]@{
  env = [ordered]@{
    COMPUTERNAME=$env:COMPUTERNAME
    PROCESSOR_ARCHITECTURE=$env:PROCESSOR_ARCHITECTURE
    NUMBER_OF_PROCESSORS=$env:NUMBER_OF_PROCESSORS
    USERNAME=$env:USERNAME
  }
  computer = Get-CimInstance Win32_ComputerSystem | Select-Object Name,Manufacturer,Model,NumberOfLogicalProcessors,TotalPhysicalMemory
  os = Get-CimInstance Win32_OperatingSystem | Select-Object Caption,Version,BuildNumber,OSArchitecture,FreePhysicalMemory,TotalVisibleMemorySize
  cpu = @(Get-CimInstance Win32_Processor | Select-Object Name,Manufacturer,NumberOfCores,NumberOfLogicalProcessors)
  display = @(Get-CimInstance Win32_VideoController | Select-Object Name,AdapterCompatibility,DriverVersion,VideoProcessor)
  net = @(Get-NetAdapter | Select-Object Name,InterfaceDescription,Status,LinkSpeed,MacAddress)
  ip = $ip
  disks = @(Get-Volume | Select-Object DriveLetter,FileSystem,Size,SizeRemaining)
  dnsLookup = $dns
  httpsEgress = $https
} | ConvertTo-Json -Depth 5 -Compress
"""


def lane_windows():
    evidence = {"runtime": "windows-hcs/docker", "host": host_census(), "steps": []}
    docker = command("docker")
    if not docker:
        return evidence | {
            "classification": "NEGATIVE_OBSERVATION",
            "oracleSatisfied": False,
            "reason": "docker CLI not present on Windows runner",
        }

    with tempfile.TemporaryDirectory(prefix="win-container-") as td:
        root = pathlib.Path(td)
        (root / "probe.ps1").write_text(windows_probe_script())
        (root / "Dockerfile").write_text(
            "FROM mcr.microsoft.com/windows/servercore:ltsc2025\n"
            "SHELL [\"powershell\",\"-NoProfile\",\"-NonInteractive\",\"-Command\"]\n"
            "COPY probe.ps1 C:/probe.ps1\n"
            "ENTRYPOINT [\"powershell\",\"-NoProfile\",\"-NonInteractive\",\"-File\",\"C:\\\\probe.ps1\"]\n"
        )
        tag = f"agent-dispatch/windows-substrate:{uuid.uuid4().hex[:8]}"
        build = run([docker, "build", "--pull", "-t", tag, str(root)], timeout=600)
        evidence["steps"].append({"build": build})
        if not ok(build):
            return evidence | {
                "classification": "ENVIRONMENT_FAILURE",
                "oracleSatisfied": False,
                "reason": "Windows container image build failed",
            }
        inspect = run([docker, "image", "inspect", tag], timeout=30)
        run_result = run([docker, "run", "--rm", "--isolation=process", tag], timeout=180)
        evidence["steps"].append({"image_inspect": inspect, "run": run_result})
        cleanup = run([docker, "image", "rm", "-f", tag], timeout=60)
        evidence["cleanup"] = cleanup
        passed = ok(run_result) and bool(run_result.get("stdout", "").strip())
        return evidence | {
            "classification": "SUPPORTED" if passed else "ORACLE_FAILURE",
            "oracleSatisfied": passed,
            "reason": "built and exercised a Windows process-isolated container" if passed else "Windows image built but process-isolated container oracle failed",
            "container_census": parse_json_stdout(run_result),
            "container_census_raw": run_result.get("stdout") if parse_json_stdout(run_result) is None else None,
            "isolation": "process",
        }


def lane_apple(runtime=None):
    evidence = {"runtime": "apple/container", "host": host_census(), "steps": []}
    cli = runtime or command("container")
    if not cli or not pathlib.Path(cli).exists():
        return evidence | {
            "classification": "NEGATIVE_OBSERVATION",
            "oracleSatisfied": False,
            "reason": "apple/container CLI not available after preparation",
        }

    version = run([cli, "system", "version", "--format", "json"], timeout=30)
    evidence["steps"].append({"version": version})
    start = run([cli, "system", "start", "--enable-kernel-install", "--timeout", "60"], timeout=180)
    evidence["steps"].append({"system_start": start})
    if not ok(start):
        return evidence | {
            "classification": "NEGATIVE_OBSERVATION",
            "oracleSatisfied": False,
            "reason": "container CLI built/callable but Virtualization.framework-backed service did not start on this hosted runner",
        }

    status = run([cli, "system", "status", "--format", "json"], timeout=30)
    evidence["steps"].append({"status": status})
    with tempfile.TemporaryDirectory(prefix="apple-container-") as td:
        root = pathlib.Path(td)
        (root / "Dockerfile").write_text(
            "FROM docker.io/library/alpine:3.22\n"
            "RUN apk add --no-cache iproute2 util-linux\n"
            "CMD [\"/bin/sh\"]\n"
        )
        tag = f"agent-dispatch/apple-substrate:{uuid.uuid4().hex[:8]}"
        build = run([cli, "build", "--tag", tag, str(root)], timeout=600)
        evidence["steps"].append({"build": build})
        if ok(build):
            inner = run([cli, "run", "--rm", tag, "sh", "-lc", LINUX_INNER], timeout=180)
        else:
            inner = {"exit_code": None, "stdout": "", "stderr": "build failed"}
        evidence["steps"].append({"run": inner})
        cleanup = run([cli, "image", "delete", tag], timeout=60)
        evidence["cleanup"] = cleanup
    stop = run([cli, "system", "stop"], timeout=60)
    evidence["steps"].append({"system_stop": stop})
    passed = ok(build) and ok(inner)
    virtualization_negative = (
        not ok(build)
        and "Virtualization is not available on this hardware" in build.get("stderr", "")
    )
    classification = "SUPPORTED" if passed else (
        "NEGATIVE_OBSERVATION" if virtualization_negative else "ORACLE_FAILURE"
    )
    reason = (
        "built and exercised an Apple container Linux VM"
        if passed
        else (
            "Apple container control plane is callable, but this hosted Mac reports no usable nested virtualization for the Linux VM"
            if virtualization_negative
            else "Apple container service started but build/run oracle failed"
        )
    )
    return evidence | {
        "classification": classification,
        "oracleSatisfied": passed,
        "reason": reason,
        "container_census": parse_sections(inner.get("stdout", "")),
        "container_census_raw": inner.get("stdout") if inner.get("stdout") else None,
        "virtualization_available": False if virtualization_negative else None,
        "isolation": "lightweight-linux-vm-per-container",
    }


def ensure_lxc_bridge():
    if not command("ip"):
        return
    have = run(["ip", "link", "show", "lxcbr0"])
    if ok(have):
        return
    if command("systemctl"):
        run(["systemctl", "start", "lxc-net"], timeout=30)


def lane_lxc():
    evidence = {"runtime": "lxc", "host": host_census(), "steps": []}
    required = ["lxc-create", "lxc-start", "lxc-attach", "lxc-destroy"]
    if any(not command(x) for x in required):
        return evidence | {
            "classification": "NEGATIVE_OBSERVATION",
            "oracleSatisfied": False,
            "reason": "LXC tools not available after preparation",
        }
    ensure_lxc_bridge()
    name = f"gha-lxc-{uuid.uuid4().hex[:8]}"
    arch = "amd64" if platform.machine().lower() in ("x86_64", "amd64") else "arm64"
    create = run([
        "lxc-create", "-n", name, "-t", "download", "--",
        "-d", "alpine", "-r", "3.22", "-a", arch,
    ], timeout=300)
    evidence["steps"].append({"create": create})
    if not ok(create):
        return evidence | {
            "classification": "ENVIRONMENT_FAILURE",
            "oracleSatisfied": False,
            "reason": "LXC rootfs creation failed",
        }
    config = pathlib.Path("/var/lib/lxc") / name / "config"
    try:
        with config.open("a") as fp:
            fp.write("\nlxc.net.0.type = veth\n")
            fp.write("lxc.net.0.link = lxcbr0\n")
            fp.write("lxc.net.0.flags = up\n")
    except Exception as exc:
        evidence["config_warning"] = str(exc)
    start = run(["lxc-start", "-n", name, "-d"], timeout=60)
    evidence["steps"].append({"start": start})
    inner = {"exit_code": None, "stdout": "", "stderr": "not started"}
    if ok(start):
        time.sleep(3)
        inner = run(["lxc-attach", "-n", name, "--", "sh", "-lc", LINUX_INNER], timeout=120)
        evidence["steps"].append({"attach_census": inner})
    stop = run(["lxc-stop", "-n", name, "-k"], timeout=30)
    destroy = run(["lxc-destroy", "-n", name], timeout=60)
    evidence["cleanup"] = {"stop": stop, "destroy": destroy}
    passed = ok(start) and ok(inner) and ok(destroy)
    return evidence | {
        "classification": "SUPPORTED" if passed else "ORACLE_FAILURE",
        "oracleSatisfied": passed,
        "reason": "created, started, entered, censused, and destroyed a real LXC system container" if passed else "LXC lifecycle or census oracle failed",
        "container_census": parse_sections(inner.get("stdout", "")),
        "container_census_raw": inner.get("stdout"),
        "isolation": "shared-linux-kernel-system-container",
    }


def lane_incus():
    evidence = {"runtime": "incus", "host": host_census(), "steps": []}
    incus = command("incus")
    if not incus:
        return evidence | {
            "classification": "NEGATIVE_OBSERVATION",
            "oracleSatisfied": False,
            "reason": "Incus CLI not available after preparation",
        }
    init = run([incus, "admin", "init", "--minimal"], timeout=90)
    evidence["steps"].append({"init": init})
    name = f"gha-incus-{uuid.uuid4().hex[:8]}"
    launch = run([incus, "launch", "images:alpine/3.22", name], timeout=300)
    evidence["steps"].append({"launch": launch})
    inner = {"exit_code": None, "stdout": "", "stderr": "not launched"}
    if ok(launch):
        for _ in range(15):
            state = run([incus, "info", name], timeout=15)
            if "Status: RUNNING" in state.get("stdout", ""):
                break
            time.sleep(2)
        inner = run([incus, "exec", name, "--", "sh", "-lc", LINUX_INNER], timeout=120)
        evidence["steps"].append({"exec_census": inner})
        evidence["instance_config"] = run([incus, "config", "show", name, "--expanded"], timeout=30)
        evidence["networks"] = run([incus, "network", "list", "--format", "json"], timeout=30)
    delete = run([incus, "delete", name, "--force"], timeout=60)
    evidence["cleanup"] = delete
    passed = ok(launch) and ok(inner) and ok(delete)
    return evidence | {
        "classification": "SUPPORTED" if passed else "ORACLE_FAILURE",
        "oracleSatisfied": passed,
        "reason": "created, entered, censused, and destroyed a real Incus system container" if passed else "Incus lifecycle or census oracle failed",
        "container_census": parse_sections(inner.get("stdout", "")),
        "container_census_raw": inner.get("stdout"),
        "isolation": "shared-linux-kernel-system-container",
    }


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--lane", choices=["windows", "apple", "lxc", "incus"], required=True)
    parser.add_argument("--out", required=True)
    parser.add_argument("--runtime")
    args = parser.parse_args()

    if args.lane == "windows":
        payload = lane_windows()
    elif args.lane == "apple":
        payload = lane_apple(args.runtime)
    elif args.lane == "lxc":
        payload = lane_lxc()
    else:
        payload = lane_incus()

    payload = {
        "schema": VERSION,
        "lane": args.lane,
        "timestamp_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        **payload,
    }
    out = pathlib.Path(args.out)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(payload, indent=2, sort_keys=True))
    print(json.dumps({
        "lane": args.lane,
        "classification": payload.get("classification"),
        "oracleSatisfied": payload.get("oracleSatisfied"),
        "reason": payload.get("reason"),
    }, indent=2))


if __name__ == "__main__":
    main()
