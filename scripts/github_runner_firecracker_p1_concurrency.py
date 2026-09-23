#!/usr/bin/env python3
"""P1 same-host Firecracker concurrency frontier for the fixed F3 capsule."""
from __future__ import annotations

import argparse
import concurrent.futures
import hashlib
import json
import os
import pathlib
import platform
import threading
import time
import tempfile
import sys

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
import github_runner_firecracker_f0 as f0
import github_runner_firecracker_f1_boot as f1
import github_runner_firecracker_f3_useful_work as f3
from firecracker_lifecycle_timing import LifecycleTimer

POINTS = (1, 2, 4)
SCHEMA = "firecracker-p1-concurrency-receipt/v1"
PROBE_VERSION = "firecracker-p1-concurrency/1"


def _cpu_identity() -> dict:
    model = None
    flags = None
    try:
        for line in pathlib.Path("/proc/cpuinfo").read_text().splitlines():
            if model is None and line.startswith("model name"):
                model = line.split(":", 1)[1].strip()
            elif flags is None and line.startswith("flags"):
                flags = " ".join(sorted(line.split(":", 1)[1].split()))
            if model and flags:
                break
    except OSError:
        pass
    return {
        "logical_cpus": os.cpu_count(),
        "model": model,
        "flags_sha256": hashlib.sha256((flags or "").encode()).hexdigest() if flags is not None else None,
    }


def _meminfo() -> dict:
    values = {}
    try:
        for line in pathlib.Path("/proc/meminfo").read_text().splitlines():
            key, rest = line.split(":", 1)
            if key in {"MemTotal", "MemAvailable"}:
                values[key] = int(rest.strip().split()[0]) * 1024
    except OSError:
        pass
    return {
        "total_bytes": values.get("MemTotal"),
        "available_bytes": values.get("MemAvailable"),
    }


def _cpu_ticks() -> tuple[int, int]:
    line = pathlib.Path("/proc/stat").read_text().splitlines()[0]
    parts = [int(x) for x in line.split()[1:]]
    total = sum(parts)
    idle = parts[3] + (parts[4] if len(parts) > 4 else 0)
    return total, idle


def _cpu_busy_percent(before: tuple[int, int], after: tuple[int, int]) -> float | None:
    total_delta = after[0] - before[0]
    idle_delta = after[1] - before[1]
    if total_delta <= 0:
        return None
    return round(100.0 * (total_delta - idle_delta) / total_delta, 3)


def _vm_rss_snapshot(binary_name: str) -> tuple[int, int]:
    count = 0
    rss_total = 0
    proc = pathlib.Path("/proc")
    for entry in proc.iterdir():
        if not entry.name.isdigit():
            continue
        try:
            exe_name = (entry / "exe").resolve().name
            if exe_name != binary_name:
                continue
            status = (entry / "status").read_text()
            rss_kib = 0
            for line in status.splitlines():
                if line.startswith("VmRSS:"):
                    rss_kib = int(line.split()[1])
                    break
            count += 1
            rss_total += rss_kib * 1024
        except (OSError, ValueError):
            continue
    return count, rss_total


def _monitor(binary_name: str, stop: threading.Event, sample: dict) -> None:
    peak_count = 0
    peak_rss = 0
    min_available = None
    while not stop.is_set():
        count, rss = _vm_rss_snapshot(binary_name)
        mem = _meminfo().get("available_bytes")
        peak_count = max(peak_count, count)
        peak_rss = max(peak_rss, rss)
        if mem is not None:
            min_available = mem if min_available is None else min(min_available, mem)
        time.sleep(0.02)
    sample.update(
        {
            "peak_firecracker_processes_observed": peak_count,
            "peak_firecracker_rss_bytes": peak_rss,
            "minimum_mem_available_bytes": min_available,
        }
    )


def _run_point(n: int, firecracker: pathlib.Path, config_path: pathlib.Path, expected: dict) -> dict:
    barrier = threading.Barrier(n + 1)
    monitor_stop = threading.Event()
    monitor_sample: dict = {}
    monitor = threading.Thread(
        target=_monitor,
        args=(firecracker.name, monitor_stop, monitor_sample),
        daemon=True,
    )

    def worker(index: int) -> dict:
        barrier.wait()
        started = time.perf_counter()
        result = f3.run_vm(firecracker, config_path, expected)
        ended = time.perf_counter()
        return {
            "index": index,
            "elapsed_ms": round((ended - started) * 1000.0, 3),
            "classification": result.get("classification"),
            "ok": bool(result.get("ok")),
            "candidate_result": result.get("candidate_result"),
            "candidate_exit": result.get("candidate_exit"),
            "kernel_to_init_ms": result.get("kernel_to_init_ms"),
            "clean_vmm_exit_observed": result.get("clean_vmm_exit_observed"),
        }

    cpu_before = _cpu_ticks()
    mem_before = _meminfo()
    load_before = os.getloadavg() if hasattr(os, "getloadavg") else None
    monitor.start()
    with concurrent.futures.ThreadPoolExecutor(max_workers=n) as pool:
        futures = [pool.submit(worker, i) for i in range(n)]
        point_started = time.perf_counter()
        barrier.wait()
        workers = [future.result() for future in futures]
        point_ended = time.perf_counter()
    monitor_stop.set()
    monitor.join(timeout=1.0)
    cpu_after = _cpu_ticks()
    mem_after = _meminfo()
    load_after = os.getloadavg() if hasattr(os, "getloadavg") else None

    elapsed = [worker["elapsed_ms"] for worker in workers]
    all_ok = all(worker["ok"] for worker in workers)
    return {
        "n": n,
        "classification": "SUPPORTED" if all_ok else "ORACLE_FAILURE",
        "all_oracles_satisfied": all_ok,
        "aggregate_makespan_ms": round((point_ended - point_started) * 1000.0, 3),
        "per_vm_elapsed_ms": elapsed,
        "per_vm": workers,
        "host": {
            "cpu_busy_percent_during_point": _cpu_busy_percent(cpu_before, cpu_after),
            "memory_before": mem_before,
            "memory_after": mem_after,
            "loadavg_before": load_before,
            "loadavg_after": load_after,
            **monitor_sample,
        },
    }


def run_probe(label: str, points: tuple[int, ...] = POINTS) -> dict:
    timer = LifecycleTimer()
    planned_count = len(points)
    if platform.system() != "Linux" or platform.machine() not in {"x86_64", "amd64"}:
        return {"schema": SCHEMA, "result": {"classification": "SETUP_REQUIRED"}}

    data = f3.DEFAULT_INPUT.read_bytes()
    expected = f3.expected_result(data)
    vm = f1._load_json(f3.VMM_MANIFEST)
    km = f1._load_json(f3.KERNEL_MANIFEST)

    with tempfile.TemporaryDirectory(prefix="firecracker-p1-") as td:
        w = pathlib.Path(td)
        archive, kernel = w / "firecracker.tgz", w / "vmlinux"
        extract = w / "vmm"
        extract.mkdir()
        init_bin, cand_bin = w / "init", w / "candidate"
        initrd, config_path = w / "initrd.cpio", w / "vm-config.json"

        with timer.stage("vmm_download_and_verify", "venue"):
            vv = f1._download_and_verify(vm["archive_url"], vm["archive_sha256"], archive)
        with timer.stage("vmm_extract", "portable"):
            f0._safe_extract(archive, extract)
            fc = f1._find_firecracker(extract, vm["version"], vm["architecture"])
        with timer.stage("kernel_download_and_verify", "venue"):
            kv = f1._download_and_verify(km["kernel_url"], km["kernel_sha256"], kernel)
        with timer.stage("candidate_compile", "portable"):
            cc = f1._compile_init(f3.CANDIDATE_SOURCE, cand_bin)
        with timer.stage("guest_init_compile", "portable"):
            ic = f1._compile_init(f3.INIT_SOURCE, init_bin)
        if not vv["verified"] or not kv["verified"] or not cc["ok"] or not ic["ok"]:
            return {"schema": SCHEMA, "result": {"classification": "HARNESS_FAILURE"}}
        with timer.stage("capsule_initramfs_build", "portable"):
            f3.build_initramfs(init_bin, cand_bin, data, initrd)
        with timer.stage("vm_config_build", "portable"):
            config = f1._build_config(kernel, initrd, config_path)

        points = []
        for rep_index, n in enumerate(points):
            with timer.stage(f"concurrency_rep{rep_index}_n{n}", "portable"):
                point = _run_point(n, fc, config_path, expected)
            points.append(point)
            if not point["all_oracles_satisfied"]:
                break

        baseline = points[0]["aggregate_makespan_ms"] if points else None
        for point in points:
            point["slowdown_vs_n1"] = (
                round(point["aggregate_makespan_ms"] / baseline, 4)
                if baseline and baseline > 0
                else None
            )
            point["throughput_vms_per_second"] = (
                round(1000.0 * point["n"] / point["aggregate_makespan_ms"], 4)
                if point["aggregate_makespan_ms"] > 0
                else None
            )

        all_passed = len(points) == planned_count and all(p["all_oracles_satisfied"] for p in points)
        largest_stable = max((p["n"] for p in points if p["all_oracles_satisfied"]), default=0)
        first_unstable = next((p["n"] for p in points if not p["all_oracles_satisfied"]), None)

        return {
            "schema": SCHEMA,
            "probe_version": PROBE_VERSION,
            "authority": "SemperSupra/agent-dispatch-private#280",
            "requested_label": label,
            "result": {
                "classification": "SUPPORTED" if all_passed else "PARTIAL_FRONTIER",
                "largest_observed_stable_n": largest_stable,
                "first_observed_unstable_n": first_unstable,
                "all_planned_points_passed": all_passed,
            },
            "fixed_capsule": {
                "input_sha256": f3.sha256_bytes(data),
                "candidate_binary_sha256": f1._sha256(cand_bin),
                "guest_init_binary_sha256": f1._sha256(init_bin),
                "initrd_sha256": f1._sha256(initrd),
                "vmm_version": vm["version"],
                "vmm_archive_sha256": vv["actual_sha256"],
                "kernel_version": km["kernel_version"],
                "kernel_sha256": kv["actual_sha256"],
                "machine": {
                    "vcpu_count_per_vm": config["machine-config"]["vcpu_count"],
                    "mem_size_mib_per_vm": config["machine-config"]["mem_size_mib"],
                    "drives": 0,
                    "network_interfaces": 0,
                },
            },
            "host_identity": {
                "cpu": _cpu_identity(),
                "image_os": os.environ.get("ImageOS"),
                "image_version": os.environ.get("ImageVersion"),
                "kernel_release": platform.release(),
                "memory": _meminfo(),
            },
            "points": points,
            "lifecycle_timing": timer.receipt(),
            "sovereign_transfer": {
                "portable_contract_depends_on_github_actions": False,
                "interpretation": "GHA is a methodology/concurrency probe; absolute capacity is not a sovereign-host forecast.",
            },
        }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--label", required=True)
    parser.add_argument("--out", type=pathlib.Path, required=True)
    parser.add_argument("--points", default="1,2,4", help="comma-separated bounded concurrency points")
    args = parser.parse_args()
    args.out.parent.mkdir(parents=True, exist_ok=True)
    try:
        points = tuple(int(value) for value in args.points.split(",") if value.strip())
        if not points or any(value < 1 or value > 8 for value in points):
            raise ValueError("points must contain integers in the range 1..8")
        receipt = run_probe(args.label, points)
    except Exception as exc:
        receipt = {
            "schema": SCHEMA,
            "result": {"classification": "HARNESS_FAILURE", "reason": f"{type(exc).__name__}: {exc}"},
        }
    args.out.write_text(json.dumps(receipt, indent=2, sort_keys=True) + "\n")
    print(json.dumps(receipt, indent=2, sort_keys=True))
    return 0 if receipt["result"]["classification"] in {"SUPPORTED", "PARTIAL_FRONTIER"} else 1


if __name__ == "__main__":
    raise SystemExit(main())
