#!/usr/bin/env python3
"""Bounded macOS GitHub-hosted runner privilege and reclaimable-memory probe."""

from __future__ import annotations

import argparse
import json
import os
import pathlib
import platform
import re
import shutil
import subprocess
import time
from typing import Any

SCHEMA = "macos-memory-privilege-envelope/v1"
PROBE_VERSION = "public-macos-memory-privilege/1"


def run(argv: list[str], timeout: int = 30, *, discard_stdout: bool = False) -> dict[str, Any]:
    try:
        cp = subprocess.run(
            argv,
            check=False,
            text=True,
            stdout=subprocess.DEVNULL if discard_stdout else subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=timeout,
        )
        return {
            "exit_code": cp.returncode,
            "stdout": None if discard_stdout else (cp.stdout[-12000:] if cp.stdout else None),
            "stderr": cp.stderr[-6000:] if cp.stderr else None,
        }
    except subprocess.TimeoutExpired as exc:
        out = exc.stdout.decode() if isinstance(exc.stdout, bytes) else exc.stdout
        err = exc.stderr.decode() if isinstance(exc.stderr, bytes) else exc.stderr
        return {
            "exit_code": None,
            "timeout": True,
            "stdout": out[-12000:] if out else None,
            "stderr": err[-6000:] if err else None,
        }
    except OSError as exc:
        return {"exit_code": None, "error": f"{type(exc).__name__}: {exc}"}


def one(argv: list[str], timeout: int = 20) -> str | None:
    r = run(argv, timeout=timeout)
    if r.get("exit_code") == 0 and r.get("stdout"):
        return str(r["stdout"]).strip()
    return None


def parse_vm_stat(raw: str | None) -> dict[str, Any]:
    if not raw:
        return {}
    page_size = None
    m = re.search(r"page size of (\d+) bytes", raw)
    if m:
        page_size = int(m.group(1))
    pages: dict[str, int] = {}
    for line in raw.splitlines():
        m = re.match(r"([^:]+):\s+([0-9]+)\.", line.strip())
        if m:
            pages[m.group(1).strip()] = int(m.group(2))
    out: dict[str, Any] = {"page_size": page_size, "pages": pages}
    if page_size:
        out["free_bytes"] = pages.get("Pages free", 0) * page_size
        out["inactive_bytes"] = pages.get("Pages inactive", 0) * page_size
        out["speculative_bytes"] = pages.get("Pages speculative", 0) * page_size
        out["purgeable_bytes"] = pages.get("Pages purgeable", 0) * page_size
        out["compressed_bytes"] = pages.get("Pages occupied by compressor", 0) * page_size
    return out


def physmem_line() -> str | None:
    r = run(["top", "-l", "1", "-s", "0", "-n", "0"], timeout=20)
    if r.get("exit_code") != 0:
        return None
    for line in (r.get("stdout") or "").splitlines():
        if line.startswith("PhysMem:"):
            return line.strip()
    return None


def top_processes(limit: int = 25) -> list[dict[str, Any]]:
    r = run(["ps", "-axo", "pid=,user=,rss=,comm=", "-r"], timeout=15)
    if r.get("exit_code") != 0:
        return []
    out: list[dict[str, Any]] = []
    for line in (r.get("stdout") or "").splitlines():
        parts = line.strip().split(None, 3)
        if len(parts) < 4:
            continue
        try:
            pid, user, rss_kib, command = int(parts[0]), parts[1], int(parts[2]), parts[3]
        except ValueError:
            continue
        out.append({"pid": pid, "user": user, "rss_kib": rss_kib, "command": command})
        if len(out) >= limit:
            break
    return out


def memory_snapshot(stage: str) -> dict[str, Any]:
    total = one(["sysctl", "-n", "hw.memsize"])
    pressure = run(["memory_pressure", "-Q"], timeout=20) if shutil.which("memory_pressure") else {}
    vm_raw = one(["vm_stat"])
    swap = one(["sysctl", "-n", "vm.swapusage"])
    pressure_level = one(["sysctl", "-n", "kern.memorystatus_vm_pressure_level"])
    df = run(["df", "-k", "/"], timeout=10)
    return {
        "stage": stage,
        "timestamp_epoch": time.time(),
        "total_bytes": int(total) if total and total.isdigit() else None,
        "physmem": physmem_line(),
        "memory_pressure": pressure,
        "vm_stat": parse_vm_stat(vm_raw),
        "swapusage": swap,
        "pressure_level": pressure_level,
        "root_df_k": df.get("stdout"),
        "top_processes": top_processes(),
    }


def process_matches(patterns: tuple[str, ...]) -> list[dict[str, Any]]:
    matches = []
    for p in top_processes(200):
        c = p["command"].lower()
        if any(x.lower() in c for x in patterns):
            matches.append(p)
    return matches


def privilege_probe() -> dict[str, Any]:
    uid = one(["id", "-u"])
    user = one(["id", "-un"])
    groups = one(["id", "-Gn"])
    sudo_true = run(["sudo", "-n", "true"], timeout=10) if shutil.which("sudo") else {"exit_code": None, "error": "sudo absent"}
    sudo_uid = run(["sudo", "-n", "id", "-u"], timeout=10) if shutil.which("sudo") else {}
    sudo_groups = run(["sudo", "-n", "id", "-Gn"], timeout=10) if shutil.which("sudo") else {}

    test_path = f"/private/tmp/agent-dispatch-root-probe-{os.getpid()}"
    root_write = run(
        ["sudo", "-n", "sh", "-c", f"umask 077; printf probe > {test_path}; chown root:wheel {test_path}"],
        timeout=10,
    ) if shutil.which("sudo") else {}
    stat = run(["stat", "-f", "%Su:%Sg:%Sp", test_path], timeout=10) if pathlib.Path(test_path).exists() else {}
    cleanup = run(["sudo", "-n", "rm", "-f", test_path], timeout=10) if shutil.which("sudo") else {}

    launchd = run(["sudo", "-n", "launchctl", "print", "system"], timeout=15, discard_stdout=True) if shutil.which("sudo") else {}
    system_writable = run(["sudo", "-n", "test", "-w", "/System"], timeout=10) if shutil.which("sudo") else {}
    data_writable = run(["sudo", "-n", "test", "-w", "/Library"], timeout=10) if shutil.which("sudo") else {}

    sip = run(["csrutil", "status"], timeout=10) if shutil.which("csrutil") else {"exit_code": None, "error": "csrutil absent"}

    return {
        "ordinary_identity": {"uid": uid, "user": user, "groups": groups},
        "passwordless_sudo": sudo_true,
        "sudo_identity": sudo_uid,
        "sudo_groups": sudo_groups,
        "root_write_test": root_write,
        "root_write_stat": stat,
        "root_write_cleanup": cleanup,
        "system_launchd_query_as_root": launchd,
        "root_test_writable_System": system_writable,
        "root_test_writable_Library": data_writable,
        "sip_status": sip,
    }


def metal_smoke() -> dict[str, Any]:
    xcrun = shutil.which("xcrun")
    if not xcrun:
        return {"classification": "HARNESS_FAILURE", "reason": "xcrun absent"}
    source = r'''
import Foundation
import Metal
if let d = MTLCreateSystemDefaultDevice() {
    print("device=\(d.name)")
    if let q = d.makeCommandQueue(), let b = q.makeCommandBuffer() {
        b.commit()
        b.waitUntilCompleted()
        print("status=\(b.status.rawValue)")
        exit(b.status == .completed ? 0 : 3)
    }
}
exit(2)
'''
    import tempfile
    with tempfile.TemporaryDirectory(prefix="memory-priv-metal-") as td:
        src = pathlib.Path(td) / "probe.swift"
        exe = pathlib.Path(td) / "probe"
        src.write_text(source, encoding="utf-8")
        cc = run([xcrun, "--sdk", "macosx", "swiftc", "-O", "-framework", "Metal", str(src), "-o", str(exe)], timeout=90)
        if cc.get("exit_code") != 0:
            return {"classification": "HARNESS_FAILURE", "compile": cc}
        rr = run([str(exe)], timeout=30)
        return {
            "classification": "SUPPORTED" if rr.get("exit_code") == 0 else "ORACLE_FAILURE",
            "run": rr,
        }


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--label", required=True)
    ap.add_argument("--out", required=True)
    args = ap.parse_args()

    receipt: dict[str, Any] = {
        "schema": SCHEMA,
        "probe_version": PROBE_VERSION,
        "provenance": {
            "requested_label": args.label,
            "run_id": os.environ.get("GITHUB_RUN_ID"),
            "run_attempt": os.environ.get("GITHUB_RUN_ATTEMPT"),
            "workflow_sha": os.environ.get("GITHUB_SHA"),
            "image_os": os.environ.get("ImageOS"),
            "image_version": os.environ.get("ImageVersion"),
        },
        "host": {
            "system": platform.system(),
            "machine": platform.machine(),
            "cpu_brand": one(["sysctl", "-n", "machdep.cpu.brand_string"]),
            "hw_model": one(["sysctl", "-n", "hw.model"]),
            "os_version": one(["sw_vers", "-productVersion"]),
            "os_build": one(["sw_vers", "-buildVersion"]),
        },
        "privilege": {},
        "snapshots": [],
        "reclaim_actions": [],
        "post_reclaim_metal": None,
        "guardrails": [
            "no launchd service disable/bootout",
            "no SIP mutation",
            "no swap/sysctl mutation",
            "no arbitrary process killing",
            "no host/hypervisor mutation",
        ],
    }

    if platform.system() != "Darwin":
        receipt["classification"] = "SKIPPED_GUARDRAIL"
        receipt["reason"] = "macOS-only probe"
    else:
        receipt["privilege"] = privilege_probe()
        receipt["snapshots"].append(memory_snapshot("baseline"))

        simulator_before = process_matches(("CoreSimulator", "/Simulator.app/", "SimulatorTrampoline"))
        sim_action: dict[str, Any] = {"kind": "simulator-shutdown", "processes_before": simulator_before}
        if simulator_before and shutil.which("xcrun"):
            sim_action["result"] = run(["xcrun", "simctl", "shutdown", "all"], timeout=60)
            time.sleep(3)
            sim_action["processes_after"] = process_matches(("CoreSimulator", "/Simulator.app/", "SimulatorTrampoline"))
            receipt["snapshots"].append(memory_snapshot("after-simulator-shutdown"))
        else:
            sim_action["classification"] = "SKIPPED_NOT_RUNNING"
        receipt["reclaim_actions"].append(sim_action)

        purge_path = shutil.which("purge")
        purge_action: dict[str, Any] = {"kind": "purge", "path": purge_path}
        if purge_path:
            before = memory_snapshot("pre-purge")
            purge_action["before"] = {
                "physmem": before.get("physmem"),
                "memory_pressure": before.get("memory_pressure"),
                "vm_stat": before.get("vm_stat"),
            }
            purge_action["result"] = run(["sudo", "-n", purge_path], timeout=120)
            time.sleep(5)
            after = memory_snapshot("after-purge")
            purge_action["after"] = {
                "physmem": after.get("physmem"),
                "memory_pressure": after.get("memory_pressure"),
                "vm_stat": after.get("vm_stat"),
            }
            receipt["snapshots"].append(after)
        else:
            purge_action["classification"] = "UNAVAILABLE"
        receipt["reclaim_actions"].append(purge_action)

        receipt["post_reclaim_metal"] = metal_smoke()
        receipt["classification"] = "OBSERVED"
        receipt["reason"] = "bounded privilege and memory-reclaim evidence captured"

    out = pathlib.Path(args.out)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(receipt, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(f"MACOS_MEMORY_PRIVILEGE_RECEIPT={out}")
    print(json.dumps(receipt, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
