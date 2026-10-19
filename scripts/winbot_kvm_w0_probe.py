#!/usr/bin/env python3
"""Cheap, non-privileged WinBot Linux/KVM W0 firmware + vTPM preflight.

This tests the W0 supporting host capabilities only, NOT Windows boot,
WinBot deployment, Secure Boot being enforced in a running guest, or
product provider admission. No VM is defined, no network is configured.
All swtpm state/socket paths are process- and run-owned temporary files.
Authority: mark-e-deyoung/WinBot#108.
"""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import time
from typing import Any


def _exec(argv: list[str], *, timeout: int = 20) -> dict[str, Any]:
    try:
        p = subprocess.run(argv, capture_output=True, text=True, timeout=timeout, check=False)
        return {"ok": p.returncode == 0, "returncode": p.returncode,
                "stdout_excerpt": p.stdout[-600:], "stderr_excerpt": p.stderr[-600:]}
    except (OSError, subprocess.TimeoutExpired) as exc:
        return {"ok": False, "error": type(exc).__name__}


def _file_digest(path: Path) -> dict[str, Any]:
    return {"path": str(path), "size": path.stat().st_size,
            "sha256": hashlib.sha256(path.read_bytes()).hexdigest()}


def _firmware_candidates() -> dict[str, Any]:
    root = Path("/usr/share/OVMF")
    keys = sorted(root.glob("OVMF_VARS*ms.fd")) + sorted(root.glob("OVMF_VARS*secboot.fd"))
    code = sorted(root.glob("OVMF_CODE*ms.fd")) + sorted(root.glob("OVMF_CODE*secboot.fd"))
    keys = [p for p in keys if p.is_file()]
    code = [p for p in code if p.is_file()]
    desc = []
    for root in (Path("/usr/share/qemu/firmware"), Path("/etc/qemu/firmware")):
        if root.is_dir():
            for p in sorted(root.glob("*.json")):
                try:
                    d = json.loads(p.read_text(encoding="utf-8"))
                except (OSError, ValueError):
                    continue
                features = d.get("features", [])
                if "secure-boot" in features and "enrolled-keys" in features:
                    desc.append({"file": str(p), "features": features})
    return {"secureboot_code": [_file_digest(p) for p in code],
            "enrolled_key_vars": [_file_digest(p) for p in keys],
            "libvirt_secureboot_descriptors": desc}


def probe_tpm2() -> dict[str, Any]:
    swtpm = shutil.which("swtpm")
    bios = shutil.which("swtpm_bios")
    if swtpm is None or bios is None:
        return {"exercised": False, "error": "swtpm or swtpm_bios absent"}
    proc: subprocess.Popen[str] | None = None
    root = None
    started = False
    result: dict[str, Any] = {"exercised": False}
    try:
        with tempfile.TemporaryDirectory(prefix="winbot-kvm-w0-") as directory:
            root = Path(directory)
            sock = root / "tpm.sock"
            ctrl = root / "ctrl.sock"
            cmd = [swtpm, "socket", "--tpm2", "--tpmstate", f"dir={directory}",
                   "--server", f"type=unixio,path={sock}",
                   "--ctrl", f"type=unixio,path={ctrl}",
                   "--flags", "not-need-init,startup-clear"]
            proc = subprocess.Popen(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            for _ in range(60):
                if proc.poll() is not None:
                    break
                if sock.exists() and ctrl.exists():
                    started = True
                    break
                time.sleep(.05)
            if started:
                # Sends an actual TPM2_Startup command across the run-owned
                # Unix socket. Version checks or installed packages alone do
                # not meet the callable/exercised W0 rung.
                result["tpm2_startup"] = _exec([bios, "--unix", str(sock), "--tpm2", "-c", "-o"], timeout=8)
                result["exercised"] = bool(result["tpm2_startup"]["ok"])
            else:
                result["error"] = "TPM 2 socket/controller did not become ready"
            result["unix_sockets_created"] = started
            result["process_running"] = proc.poll() is None
            if proc.poll() is None:
                proc.terminate()
                try:
                    proc.wait(timeout=4)
                except subprocess.TimeoutExpired:
                    proc.kill()
                    proc.wait(timeout=4)
            proc = None
    finally:
        if proc is not None and proc.poll() is None:
            proc.kill()
            proc.wait(timeout=4)
    result["run_owned_tpm_state_removed"] = bool(root is not None and not root.exists())
    return result


def main() -> int:
    probes = {
        "schema": "winbot-kvm-w0-host-observation/v1",
        "claim_boundary": "OVMF/Secure Boot candidate + TPM2 process exercise ONLY; no Windows/WinBot runtime acceptance",
        "host": {"kvm_char_device": Path("/dev/kvm").is_char_device(),
                 "virsh_present": shutil.which("virsh") is not None,
                 "swtpm_present": shutil.which("swtpm") is not None},
        "firmware": _firmware_candidates(),
        "domcapabilities": _exec(["sudo", "virsh", "-c", "qemu:///system", "domcapabilities",
                                   "--virttype", "kvm"], timeout=30),
        "tpm2": probe_tpm2(),
    }
    fw = probes["firmware"]
    # Firmware/keys are observed host capabilities. This cannot prove that a
    # future libvirt guest will actually enforce Secure Boot.
    passed = (probes["host"]["kvm_char_device"]
              and probes["domcapabilities"]["ok"]
              and len(fw["secureboot_code"]) > 0
              and len(fw["enrolled_key_vars"]) > 0
              and len(fw["libvirt_secureboot_descriptors"]) > 0
              and probes["tpm2"]["exercised"]
              and probes["tpm2"]["run_owned_tpm_state_removed"])
    probes["classification"] = "W0_PRECONDITIONS_OBSERVED" if passed else "W0_GAP_OBSERVED"
    result = Path(os.environ.get("WINBOT_W0_RECEIPT", "winbot-kvm-w0-receipt.json"))
    result.parent.mkdir(parents=True, exist_ok=True)
    result.write_text(json.dumps(probes, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps(probes, indent=2, sort_keys=True))
    # Preserve a usable machine receipt for any observed gap; a green CI job
    # is explicitly NOT a W0 PASS unless the receipt says so.
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
