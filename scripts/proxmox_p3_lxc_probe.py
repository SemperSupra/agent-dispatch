#!/usr/bin/env python3
"""Prepared Proxmox P3 oracle: pct LXC lifecycle + common execution census.

Preparation only. The real-system harness must not invoke this before P2 is
accepted. The census content is bound to Agent Dispatch container-substrate
qualification commit dd9da9961584680f331c338c50849dc93ab5f544.
"""
from __future__ import annotations

import argparse
import json
import pathlib
import subprocess
import sys

CENSUS_SOURCE_COMMIT = "dd9da9961584680f331c338c50849dc93ab5f544"
SCHEMA = "proxmox-p3-lxc/v1"

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
if command -v ip >/dev/null 2>&1; then ip addr 2>/dev/null || true
elif command -v ifconfig >/dev/null 2>&1; then ifconfig -a 2>/dev/null || true
elif command -v busybox >/dev/null 2>&1; then busybox ip addr 2>/dev/null || busybox ifconfig -a 2>/dev/null || cat /proc/net/dev 2>/dev/null || true
else cat /proc/net/dev 2>/dev/null || true
fi
echo '===ROUTES==='
if command -v ip >/dev/null 2>&1; then ip route 2>/dev/null || true
elif command -v route >/dev/null 2>&1; then route -n 2>/dev/null || true
elif command -v busybox >/dev/null 2>&1; then busybox ip route 2>/dev/null || busybox route -n 2>/dev/null || cat /proc/net/route 2>/dev/null || true
else cat /proc/net/route 2>/dev/null || true
fi
echo '===DNS==='
cat /etc/resolv.conf 2>/dev/null || true
echo '===DNS_ORACLE==='
if command -v getent >/dev/null 2>&1; then getent hosts github.com 2>&1 || true
elif command -v nslookup >/dev/null 2>&1; then nslookup github.com 2>&1 || true
elif command -v busybox >/dev/null 2>&1; then busybox nslookup github.com 2>&1 || true
else echo 'UNKNOWN no DNS query tool'
fi
echo '===TCP_443_ORACLE==='
if command -v nc >/dev/null 2>&1; then nc -zvw 8 github.com 443 2>&1 && echo PASS || echo FAIL
elif command -v busybox >/dev/null 2>&1; then busybox nc -z -w 8 github.com 443 2>&1 && echo PASS || echo FAIL
else echo 'UNKNOWN no TCP client'
fi
echo '===HTTPS_EGRESS==='
if command -v curl >/dev/null 2>&1; then curl -fsS -I --max-time 12 -w 'HTTP=%{http_code} REMOTE=%{remote_ip} CONNECT=%{time_connect} TLS=%{time_appconnect}\n' https://github.com/ 2>&1 && echo PASS || echo FAIL
elif command -v wget >/dev/null 2>&1; then wget -S -T 12 -O /dev/null https://github.com/ 2>&1 && echo PASS || echo FAIL
elif command -v busybox >/dev/null 2>&1; then busybox wget -S -T 12 -O /dev/null https://github.com/ 2>&1 && echo PASS || echo FAIL
else echo 'UNKNOWN no HTTPS client'
fi
echo '===DEVICES==='
for p in /dev/kvm /dev/dri /dev/nvidia0 /dev/nvidiactl /dev/infiniband /dev/bus/usb /dev/net/tun /dev/fuse /dev/tpm0 /dev/tpmrm0; do
  if [ -e "$p" ]; then
    ls -ld "$p" 2>/dev/null || true
    if [ -d "$p" ]; then find "$p" -maxdepth 2 -mindepth 1 -print 2>/dev/null | head -100 || true; fi
  else echo "MISSING $p"
  fi
done
echo '===FILESYSTEM==='
(df -T 2>/dev/null || df -h 2>/dev/null || true)
echo '===IDENTITY==='
(id || true)
"""

REMOTE = r'''import json, pathlib, shlex, subprocess, time

SCHEMA = "proxmox-p3-lxc/v1"
CENSUS_SOURCE_COMMIT = "dd9da9961584680f331c338c50849dc93ab5f544"
LINUX_INNER = __CENSUS__

def run(argv, timeout=120):
    try:
        cp = subprocess.run(argv, text=True, capture_output=True, timeout=timeout)
        return {"argv": argv, "rc": cp.returncode, "stdout": cp.stdout[-40000:], "stderr": cp.stderr[-12000:]}
    except subprocess.TimeoutExpired as exc:
        return {"argv": argv, "rc": 124, "stdout": (exc.stdout or "")[-40000:] if isinstance(exc.stdout, str) else "", "stderr": "timeout"}

def ok(r):
    return r.get("rc") == 0

def first_active(content):
    r = run(["pvesm", "status", "--content", content], 30)
    if not ok(r):
        return None, r
    for line in r["stdout"].splitlines()[1:]:
        cols = line.split()
        if len(cols) >= 3 and cols[2].lower() == "active":
            return cols[0], r
    return None, r

out = {
    "schema": SCHEMA,
    "classification": "ORACLE_FAILURE",
    "oracleSatisfied": False,
    "census_source_commit": CENSUS_SOURCE_COMMIT,
    "steps": {},
    "cleanup": {},
}
vmid = None
try:
    out["steps"]["pveversion"] = run(["pveversion", "-v"], 30)
    if not ok(out["steps"]["pveversion"]):
        raise RuntimeError("pveversion failed")

    root_storage, root_status = first_active("rootdir")
    tmpl_storage, tmpl_status = first_active("vztmpl")
    out["steps"]["root_storage_status"] = root_status
    out["steps"]["template_storage_status"] = tmpl_status
    if not root_storage or not tmpl_storage:
        raise RuntimeError("no active rootdir/vztmpl storage pair")

    bridges = run(["sh", "-lc", "ip -o link show type bridge | awk -F': ' '{print $2}'"], 20)
    bridge_names = [x.strip().split("@",1)[0] for x in bridges["stdout"].splitlines() if x.strip()]
    bridge = "vmbr0" if "vmbr0" in bridge_names else (bridge_names[0] if bridge_names else None)
    out["steps"]["bridges"] = bridges
    if not bridge:
        raise RuntimeError("no Linux bridge available for pct net0")

    out["steps"]["pveam_update"] = run(["pveam", "update"], 120)
    available = run(["pveam", "available", "--section", "system"], 60)
    out["steps"]["pveam_available"] = available
    if not ok(available):
        raise RuntimeError("pveam available failed")
    templates = []
    for line in available["stdout"].splitlines():
        cols = line.split()
        if len(cols) >= 2 and ("debian-13-standard_" in cols[1] or "debian-12-standard_" in cols[1]):
            templates.append(cols[1])
    templates.sort(key=lambda x: ("debian-13-standard_" not in x, x))
    if not templates:
        raise RuntimeError("no Debian standard LXC template available")
    template = templates[0]
    out["template"] = template
    out["template_storage"] = tmpl_storage
    out["root_storage"] = root_storage
    out["bridge"] = bridge

    download = run(["pveam", "download", tmpl_storage, template], 300)
    out["steps"]["template_download"] = download
    if not ok(download):
        # Cached template is acceptable if pveam download reports it already exists.
        if "already exists" not in (download.get("stderr","") + download.get("stdout","")).lower():
            raise RuntimeError("template download failed")

    nextid = run(["pvesh", "get", "/cluster/nextid", "--output-format", "json"], 30)
    out["steps"]["nextid"] = nextid
    if not ok(nextid):
        raise RuntimeError("could not allocate VMID")
    vmid = int(json.loads(nextid["stdout"]))
    out["vmid"] = vmid

    volume = f"{tmpl_storage}:vztmpl/{template}"
    create = run([
        "pct", "create", str(vmid), volume,
        "--hostname", "rdte-p3",
        "--rootfs", f"{root_storage}:2",
        "--memory", "512",
        "--cores", "1",
        "--unprivileged", "1",
        "--features", "nesting=0,keyctl=0",
        "--net0", f"name=eth0,bridge={bridge},ip=dhcp,type=veth",
        "--onboot", "0",
    ], 180)
    out["steps"]["create"] = create
    if not ok(create):
        raise RuntimeError("pct create failed")

    config = run(["pct", "config", str(vmid)], 30)
    out["steps"]["config"] = config
    if not ok(config):
        raise RuntimeError("pct config failed")

    start = run(["pct", "start", str(vmid)], 90)
    out["steps"]["start"] = start
    if not ok(start):
        raise RuntimeError("pct start failed")
    running = False
    for _ in range(30):
        status = run(["pct", "status", str(vmid)], 10)
        if ok(status) and "status: running" in status["stdout"].lower():
            running = True
            out["steps"]["running_status"] = status
            break
        time.sleep(2)
    if not running:
        raise RuntimeError("container did not reach running")

    # Give guest userspace/network a bounded settle interval, then execute the
    # same census shape used by the generic LXC qualification.
    time.sleep(3)
    census = run(["pct", "exec", str(vmid), "--", "sh", "-lc", LINUX_INNER], 180)
    out["steps"]["census"] = census
    if not ok(census):
        raise RuntimeError("pct exec census failed")
    required_markers = ["===UNAME===", "===CPU===", "===MEMINFO===", "===CGROUP===", "===NETWORK===", "===DEVICES==="]
    if not all(marker in census["stdout"] for marker in required_markers):
        raise RuntimeError("census output missing required sections")

    out["classification"] = "SUPPORTED"
    out["oracleSatisfied"] = True
    out["detail"] = "pct created, started, entered, censused, stopped, and deleted a real unprivileged LXC system container"
except Exception as exc:
    out["detail"] = f"{type(exc).__name__}: {exc}"
finally:
    if vmid is not None:
        out["cleanup"]["stop"] = run(["pct", "stop", str(vmid), "--skiplock", "1"], 60)
        out["cleanup"]["destroy"] = run(["pct", "destroy", str(vmid), "--purge", "1"], 120)
        post = run(["pct", "status", str(vmid)], 20)
        out["cleanup"]["post_status"] = post
        out["cleanup"]["config_absent"] = not pathlib.Path(f"/etc/pve/lxc/{vmid}.conf").exists()
        if out["oracleSatisfied"] and (ok(post) or not out["cleanup"]["config_absent"]):
            out["classification"] = "ORACLE_FAILURE"
            out["oracleSatisfied"] = False
            out["detail"] = "container lifecycle passed but zero-residue cleanup oracle failed"
print(json.dumps(out, sort_keys=True))
'''.replace("__CENSUS__", repr(LINUX_INNER))


def run_remote(host: str, port: int, password_file: pathlib.Path, timeout: int = 900):
    argv = [
        "sshpass", "-f", str(password_file),
        "ssh", "-p", str(port),
        "-o", "StrictHostKeyChecking=no",
        "-o", "UserKnownHostsFile=/dev/null",
        "-o", "ConnectTimeout=8",
        f"root@{host}", "python3", "-",
    ]
    cp = subprocess.run(argv, input=REMOTE, text=True, capture_output=True, timeout=timeout)
    if cp.returncode != 0:
        return {
            "schema": SCHEMA,
            "classification": "ORACLE_FAILURE",
            "oracleSatisfied": False,
            "detail": f"SSH/remote P3 driver failed rc={cp.returncode}",
            "ssh_stderr": cp.stderr[-12000:],
            "census_source_commit": CENSUS_SOURCE_COMMIT,
        }
    try:
        return json.loads(cp.stdout.strip().splitlines()[-1])
    except Exception as exc:
        return {
            "schema": SCHEMA,
            "classification": "ORACLE_FAILURE",
            "oracleSatisfied": False,
            "detail": f"remote P3 output was not JSON: {type(exc).__name__}",
            "ssh_stderr": cp.stderr[-12000:],
            "remote_stdout_tail": cp.stdout[-12000:],
            "census_source_commit": CENSUS_SOURCE_COMMIT,
        }


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--port", type=int, required=True)
    ap.add_argument("--password-file", type=pathlib.Path, required=True)
    ap.add_argument("--out", type=pathlib.Path, required=True)
    args = ap.parse_args()
    payload = run_remote(args.host, args.port, args.password_file)
    args.out.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps({
        "classification": payload.get("classification"),
        "oracleSatisfied": payload.get("oracleSatisfied"),
        "census_source_commit": CENSUS_SOURCE_COMMIT,
    }, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
