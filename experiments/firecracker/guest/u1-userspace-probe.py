#!/usr/bin/env python3
import hashlib
import json
import os
import platform
import shutil
import subprocess
import sys

payload = b"firecracker-u1-normal-userspace\n"
payload_path = "/tmp/u1-payload.bin"
result_path = "/tmp/u1-result.json"

with open(payload_path, "wb") as fh:
    fh.write(payload)
    fh.flush()
    os.fsync(fh.fileno())

with open(payload_path, "rb") as fh:
    observed = fh.read()

os_release = {}
with open("/etc/os-release", "r", encoding="utf-8") as fh:
    for raw in fh:
        if "=" not in raw:
            continue
        key, value = raw.rstrip("\n").split("=", 1)
        os_release[key] = value.strip().strip('"')

tools = {name: bool(shutil.which(name)) for name in ("curl", "fio", "ip", "strace")}
shell = subprocess.run(
    ["/bin/sh", "-c", "printf u1-shell-ok"],
    check=False,
    capture_output=True,
    text=True,
    timeout=5,
)
result = {
    "os_id": os_release.get("ID"),
    "os_version": os_release.get("VERSION_ID"),
    "python_version": platform.python_version(),
    "architecture": platform.machine(),
    "shell_ok": shell.returncode == 0 and shell.stdout == "u1-shell-ok",
    "tools": tools,
    "payload_size": len(observed),
    "payload_sha256": hashlib.sha256(observed).hexdigest(),
}

with open(result_path, "w", encoding="utf-8") as fh:
    json.dump(result, fh, sort_keys=True)
    fh.write("\n")
    fh.flush()
    os.fsync(fh.fileno())

tool_text = ",".join(f"{name}:{1 if ok else 0}" for name, ok in sorted(tools.items()))
print(
    "FIRECRACKER_U1_USERSPACE "
    f"os_id={result['os_id']} "
    f"os_version={result['os_version']} "
    f"python={result['python_version']} "
    f"arch={result['architecture']} "
    f"shell={1 if result['shell_ok'] else 0} "
    f"tools={tool_text} "
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
):
    raise SystemExit(17)
