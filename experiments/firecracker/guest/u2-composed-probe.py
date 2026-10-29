#!/usr/bin/env python3
import hashlib
import http.client
import json
import os
import platform
import shutil
import socket
import ssl
import subprocess

payload = b"firecracker-u2-jailed-network-userspace\n"
payload_path = "/tmp/u2-payload.bin"
result_path = "/tmp/u2-result.json"

with open(payload_path, "wb") as fh:
    fh.write(payload)
    fh.flush()
    os.fsync(fh.fileno())

os_release = {}
with open("/etc/os-release", "r", encoding="utf-8") as fh:
    for raw in fh:
        if "=" in raw:
            key, value = raw.rstrip("\n").split("=", 1)
            os_release[key] = value.strip().strip('"')

tools = {name: bool(shutil.which(name)) for name in ("curl", "fio", "ip", "strace")}
shell = subprocess.run(
    ["/bin/sh", "-c", "printf u2-shell-ok"],
    check=False,
    capture_output=True,
    text=True,
    timeout=5,
)

ctx = ssl.create_default_context()
conn = http.client.HTTPSConnection("example.com", 443, timeout=6, context=ctx)
conn.request("GET", "/")
resp = conn.getresponse()
body = resp.read(16384)
tls_version = conn.sock.version() if conn.sock is not None else ""
status = resp.status
conn.close()

def blocked(host, port):
    try:
        s = socket.create_connection((host, port), timeout=0.6)
    except OSError:
        return True
    else:
        s.close()
        return False

metadata_blocked = blocked("169.254.169.254", 80)
host_blocked = blocked("192.0.2.1", 80)

with open(payload_path, "rb") as fh:
    observed = fh.read()

result = {
    "os_id": os_release.get("ID"),
    "os_version": os_release.get("VERSION_ID"),
    "python_version": platform.python_version(),
    "architecture": platform.machine(),
    "shell_ok": shell.returncode == 0 and shell.stdout == "u2-shell-ok",
    "tools": tools,
    "payload_sha256": hashlib.sha256(observed).hexdigest(),
    "payload_size": len(observed),
    "https_status": status,
    "https_body_bytes": len(body),
    "tls_version": tls_version,
    "metadata_blocked": metadata_blocked,
    "host_blocked": host_blocked,
}

with open(result_path, "w", encoding="utf-8") as fh:
    json.dump(result, fh, sort_keys=True)
    fh.write("\n")
    fh.flush()
    os.fsync(fh.fileno())
os.sync()

tool_text = ",".join(f"{name}:{1 if ok else 0}" for name, ok in sorted(tools.items()))
print(
    "FIRECRACKER_U2_COMPOSED "
    f"os_id={result['os_id']} "
    f"os_version={result['os_version']} "
    f"python={result['python_version']} "
    f"arch={result['architecture']} "
    f"shell={1 if result['shell_ok'] else 0} "
    f"tools={tool_text} "
    f"https_status={status} "
    f"body_bytes={len(body)} "
    f"tls={tls_version} "
    f"metadata_blocked={1 if metadata_blocked else 0} "
    f"host_blocked={1 if host_blocked else 0} "
    f"scratch_sha256={result['payload_sha256']}",
    flush=True,
)

if not (
    result["os_id"] == "ubuntu"
    and result["os_version"] == "24.04"
    and result["architecture"] == "x86_64"
    and result["shell_ok"]
    and all(result["tools"].values())
    and result["payload_sha256"] == hashlib.sha256(payload).hexdigest()
    and 200 <= status < 400
    and len(body) > 0
    and tls_version in ("TLSv1.2", "TLSv1.3")
    and metadata_blocked
    and host_blocked
):
    raise SystemExit(27)
