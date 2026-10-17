#!/usr/bin/env python3
"""In-VM paired statistical benchmark harness for GitHub-hosted runner optimizations.

Enforces A/B/B/A block randomization, measures CPU steal time/jitter,
evaluates RAM-disk (/dev/shm) vs disk I/O, and records vectorization throughput.
"""
from __future__ import annotations

import argparse
import json
import math
import os
import platform
import shutil
import sys
import tempfile
import time
from typing import Dict, Any, List, Tuple

SCHEMA = "github-runner-optimization-receipt/v1"

def _get_cpu_steal_time() -> float:
    """Read hypervisor CPU steal ticks on Linux from /proc/stat."""
    if not os.path.exists("/proc/stat"):
        return 0.0
    try:
        with open("/proc/stat", "r") as f:
            for line in f:
                if line.startswith("cpu "):
                    parts = line.split()[1:]
                    if len(parts) >= 8:
                        return float(parts[7]) # steal ticks
    except Exception:
        pass
    return 0.0

def benchmark_ramdisk_io(n_pairs: int = 10, payload_mb: int = 32) -> Dict[str, Any]:
    """In-VM paired microbenchmark: Standard workspace disk vs /dev/shm tmpfs sequential write+fsync."""
    payload = os.urandom(payload_mb * 1024 * 1024)
    disk_dir = tempfile.mkdtemp(prefix="bench_disk_")
    
    # Check if /dev/shm is available and writable, else fallback to tempfs
    shm_available = os.path.exists("/dev/shm") and os.access("/dev/shm", os.W_OK)
    shm_dir = tempfile.mkdtemp(prefix="bench_shm_", dir="/dev/shm" if shm_available else None)
    
    disk_durations: List[float] = []
    shm_durations: List[float] = []
    paired_diffs: List[float] = []
    
    try:
        # Interleaved AB/BA pairs (consecutive pairs i, i+1 form an A-B-B-A block)
        for i in range(n_pairs):
            pair_order = ("disk", "shm") if (i % 2 == 0) else ("shm", "disk")
            pair_obs: Dict[str, float] = {}
            for mode in pair_order:
                if mode == "disk":
                    p = os.path.join(disk_dir, f"file_{i}.bin")
                    t0 = time.perf_counter()
                    with open(p, "wb") as f:
                        f.write(payload)
                        f.flush()
                        os.fsync(f.fileno())
                    elapsed = time.perf_counter() - t0
                    disk_durations.append(elapsed)
                    pair_obs["disk"] = elapsed
                    try:
                        os.unlink(p)
                    except OSError:
                        pass
                else:
                    p = os.path.join(shm_dir, f"file_{i}.bin")
                    t0 = time.perf_counter()
                    with open(p, "wb") as f:
                        f.write(payload)
                        f.flush()
                        os.fsync(f.fileno())
                    elapsed = time.perf_counter() - t0
                    shm_durations.append(elapsed)
                    pair_obs["shm"] = elapsed
                    try:
                        os.unlink(p)
                    except OSError:
                        pass
            if "disk" in pair_obs and "shm" in pair_obs:
                paired_diffs.append(pair_obs["disk"] - pair_obs["shm"])
    finally:
        shutil.rmtree(disk_dir, ignore_errors=True)
        shutil.rmtree(shm_dir, ignore_errors=True)
        
    n = len(disk_durations)
    mean_disk = sum(disk_durations) / n if n else 0.0
    mean_shm = sum(shm_durations) / len(shm_durations) if shm_durations else 0.0
    speedup = (mean_disk / mean_shm) if mean_shm > 0 else 1.0
    mean_diff = sum(paired_diffs) / len(paired_diffs) if paired_diffs else 0.0
    var_diff = (
        sum((d - mean_diff) ** 2 for d in paired_diffs) / (len(paired_diffs) - 1)
        if len(paired_diffs) > 1
        else 0.0
    )
    std_diff = math.sqrt(var_diff)
    
    return {
        "metric": "write_fsync_throughput",
        "scope": "microbenchmark_sequential_write_fsync_only",
        "design": "interleaved_ab_ba_pairs",
        "payload_mb": payload_mb,
        "n_samples": n,
        "n_abba_blocks": n // 2,
        "shm_backed_by_dev_shm": bool(shm_available),
        "disk_mean_seconds": mean_disk,
        "shm_mean_seconds": mean_shm,
        "paired_diff_mean_seconds": mean_diff,
        "paired_diff_std_seconds": std_diff,
        "speedup": speedup,
        "shm_verified_faster": bool(mean_shm < mean_disk)
    }

def benchmark_compute_vectorization(n_iterations: int = 20) -> Dict[str, Any]:
    """Measures compute / hash / memory throughput across iterations to detect thermal jitter."""
    durations: List[float] = []
    block = os.urandom(16 * 1024 * 1024) # 16 MB block
    
    import hashlib
    for i in range(n_iterations):
        t0 = time.perf_counter()
        _ = hashlib.sha256(block).hexdigest()
        elapsed = time.perf_counter() - t0
        durations.append(elapsed)
        
    mean_d = sum(durations) / len(durations)
    variance = sum((d - mean_d) ** 2 for d in durations) / (len(durations) - 1) if len(durations) > 1 else 0.0
    std_d = math.sqrt(variance)
    cv = (std_d / mean_d * 100.0) if mean_d > 0 else 0.0 # Coefficient of variation (%)
    
    return {
        "metric": "sha256_16mb_throughput",
        "n_iterations": n_iterations,
        "mean_seconds": mean_d,
        "std_seconds": std_d,
        "coefficient_of_variation_pct": cv,
        "jitter_acceptable": bool(cv < 15.0) # >15% CV indicates severe hypervisor contention
    }

def run_benchmarks(label: str = "local") -> Dict[str, Any]:
    steal_before = _get_cpu_steal_time()
    t_start = time.perf_counter()
    
    io_res = benchmark_ramdisk_io(n_pairs=10, payload_mb=32)
    compute_res = benchmark_compute_vectorization(n_iterations=20)
    
    t_end = time.perf_counter()
    steal_after = _get_cpu_steal_time()
    steal_delta = steal_after - steal_before
    
    receipt = {
        "schema": SCHEMA,
        "runner_label": label,
        "system": platform.system(),
        "machine": platform.machine(),
        "wall_clock_total_seconds": t_end - t_start,
        "hypervisor_steal_ticks": steal_delta,
        "ramdisk_benchmark": io_res,
        "compute_jitter_benchmark": compute_res,
        "warnings": [
            "32 MiB sequential write+fsync microbenchmark only; does not prove large-model RAM-disk residency or OOM safety",
            "tmpfs (/dev/shm) shares physical RAM with guest processes and reduces available model/KV-cache memory"
        ],
        "status": "PASS" if compute_res["jitter_acceptable"] else "CONTAMINATED_JITTER"
    }
    return receipt

def main():
    parser = argparse.ArgumentParser(description="In-VM runner optimization benchmark")
    parser.add_argument("--label", default="local", help="Runner label under test")
    parser.add_argument("--out", help="Write receipt JSON to path")
    args = parser.parse_args()
    
    receipt = run_benchmarks(args.label)
    print(json.dumps(receipt, indent=2))
    
    if args.out:
        os.makedirs(os.path.dirname(os.path.abspath(args.out)), exist_ok=True)
        with open(args.out, "w") as f:
            json.dump(receipt, f, indent=2)
            
if __name__ == "__main__":
    main()
