#!/usr/bin/env python3
"""P2 coexistence/interference experiment for the fixed Firecracker F3 capsule."""
from __future__ import annotations

import argparse
import concurrent.futures
import json
import os
import pathlib
import re
import shutil
import subprocess
import sys
import tempfile
import threading
import time

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
import github_runner_firecracker_f0 as f0
import github_runner_firecracker_f1_boot as f1
import github_runner_firecracker_f3_useful_work as f3
import github_runner_firecracker_p1_concurrency as p1
from firecracker_lifecycle_timing import LifecycleTimer

SCHEMA = "firecracker-p2-coexistence-receipt/v1"
PROBE_VERSION = "firecracker-p2-coexistence/1"
N_VM = 2
HELPER_SOURCE = pathlib.Path("experiments/firecracker/p2/cpu-helper-x86_64.c")
HELPER_RE = re.compile(r"P2_CPU_HELPER iterations=(\d+) elapsed_ns=(\d+)")


def _run_command(argv: list[str], timeout_s: int = 10) -> dict:
    started = time.perf_counter()
    try:
        cp = subprocess.run(argv, capture_output=True, text=True, timeout=timeout_s, check=False)
        elapsed_ms = (time.perf_counter() - started) * 1000.0
        combined = "\n".join(x for x in (cp.stdout.strip(), cp.stderr.strip()) if x)
        match = HELPER_RE.search(combined)
        return {
            "ok": cp.returncode == 0 and bool(match),
            "return_code": cp.returncode,
            "elapsed_ms": round(elapsed_ms, 3),
            "iterations": int(match.group(1)) if match else None,
            "reported_elapsed_ns": int(match.group(2)) if match else None,
            "output": combined[-2000:],
        }
    except (OSError, subprocess.SubprocessError) as exc:
        return {"ok": False, "error": f"{type(exc).__name__}: {exc}", "elapsed_ms": round((time.perf_counter()-started)*1000.0,3)}


def _prepare_docker(helper: pathlib.Path, build_dir: pathlib.Path) -> dict:
    docker = shutil.which("docker")
    if not docker:
        return {"ok": False, "reason": "docker CLI unavailable"}
    code, out, err = f0._run([docker, "info"], timeout=20)
    if code != 0:
        return {"ok": False, "reason": (err or out or "docker daemon unavailable")[-2000:]}
    image_bin = build_dir / "cpu-helper"
    shutil.copy2(helper, image_bin)
    dockerfile = build_dir / "Dockerfile"
    dockerfile.write_text("FROM scratch\nCOPY cpu-helper /cpu-helper\nENTRYPOINT [\"/cpu-helper\"]\n")
    tag = "agent-dispatch-firecracker-p2:local"
    code, out, err = f0._run(
        [docker, "build", "--network=none", "--pull=false", "-t", tag, str(build_dir)],
        timeout=60,
    )
    return {
        "ok": code == 0,
        "tag": tag,
        "reason": None if code == 0 else (err or out or f"docker build exit {code}")[-3000:],
    }


def _run_condition(kind: str, firecracker: pathlib.Path, config_path: pathlib.Path, expected: dict, helper: pathlib.Path, docker_tag: str | None) -> dict:
    helper_count = 0 if kind == "firecracker_only" else 1
    barrier = threading.Barrier(N_VM + helper_count + 1)
    monitor_stop = threading.Event()
    monitor_sample: dict = {}
    monitor = threading.Thread(target=p1._monitor, args=(firecracker.name, monitor_stop, monitor_sample), daemon=True)

    def vm_worker(index: int) -> dict:
        barrier.wait()
        started = time.perf_counter()
        result = f3.run_vm(firecracker, config_path, expected)
        ended = time.perf_counter()
        return {
            "index": index,
            "elapsed_ms": round((ended-started)*1000.0, 3),
            "ok": bool(result.get("ok")),
            "classification": result.get("classification"),
            "kernel_to_init_ms": result.get("kernel_to_init_ms"),
            "candidate_exit": result.get("candidate_exit"),
        }

    def helper_worker() -> dict:
        barrier.wait()
        if kind == "native_cpu":
            return _run_command([str(helper.resolve())], timeout_s=5)
        if kind == "docker_cpu":
            docker = shutil.which("docker")
            if not docker or not docker_tag:
                return {"ok": False, "reason": "docker unavailable"}
            return _run_command([docker, "run", "--rm", "--network=none", docker_tag], timeout_s=10)
        return {"ok": True}

    cpu_before = p1._cpu_ticks()
    mem_before = p1._meminfo()
    monitor.start()
    max_workers = N_VM + helper_count
    with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as pool:
        vm_futures = [pool.submit(vm_worker, i) for i in range(N_VM)]
        helper_future = pool.submit(helper_worker) if helper_count else None
        started = time.perf_counter()
        barrier.wait()
        vm_results = [future.result() for future in vm_futures]
        helper_result = helper_future.result() if helper_future else None
        ended = time.perf_counter()
    monitor_stop.set()
    monitor.join(timeout=1.0)
    cpu_after = p1._cpu_ticks()
    mem_after = p1._meminfo()

    vm_makespan = max(result["elapsed_ms"] for result in vm_results)
    all_vm_ok = all(result["ok"] for result in vm_results)
    helper_ok = True if helper_result is None else bool(helper_result.get("ok"))
    return {
        "condition": kind,
        "classification": "SUPPORTED" if all_vm_ok and helper_ok else "ORACLE_FAILURE",
        "all_vm_oracles_satisfied": all_vm_ok,
        "helper_oracle_satisfied": helper_ok,
        "condition_makespan_ms": round((ended-started)*1000.0,3),
        "vm_makespan_ms": vm_makespan,
        "per_vm": vm_results,
        "helper": helper_result,
        "host": {
            "cpu_busy_percent": p1._cpu_busy_percent(cpu_before,cpu_after),
            "memory_before": mem_before,
            "memory_after": mem_after,
            **monitor_sample,
        },
    }


def run_probe(label: str) -> dict:
    timer = LifecycleTimer()
    data = f3.DEFAULT_INPUT.read_bytes()
    expected = f3.expected_result(data)
    vm = f1._load_json(f3.VMM_MANIFEST)
    km = f1._load_json(f3.KERNEL_MANIFEST)

    with tempfile.TemporaryDirectory(prefix="firecracker-p2-") as td:
        w=pathlib.Path(td)
        archive,kernel=w/"firecracker.tgz",w/"vmlinux"
        extract=w/"vmm"; extract.mkdir()
        init_bin,cand_bin,helper_bin=w/"init",w/"candidate",w/"cpu-helper"
        initrd,config_path=w/"initrd.cpio",w/"vm-config.json"

        with timer.stage("vmm_download_and_verify","venue"):
            vv=f1._download_and_verify(vm["archive_url"],vm["archive_sha256"],archive)
        with timer.stage("vmm_extract","portable"):
            f0._safe_extract(archive,extract)
            fc=f1._find_firecracker(extract,vm["version"],vm["architecture"])
        with timer.stage("kernel_download_and_verify","venue"):
            kv=f1._download_and_verify(km["kernel_url"],km["kernel_sha256"],kernel)
        with timer.stage("candidate_compile","portable"):
            cc=f1._compile_init(f3.CANDIDATE_SOURCE,cand_bin)
        with timer.stage("guest_init_compile","portable"):
            ic=f1._compile_init(f3.INIT_SOURCE,init_bin)
        with timer.stage("coexistence_helper_compile","portable"):
            hc=f1._compile_init(HELPER_SOURCE,helper_bin)
        if not all([vv["verified"],kv["verified"],cc["ok"],ic["ok"],hc["ok"]]):
            return {"schema":SCHEMA,"result":{"classification":"HARNESS_FAILURE"}}
        with timer.stage("capsule_initramfs_build","portable"):
            f3.build_initramfs(init_bin,cand_bin,data,initrd)
        with timer.stage("vm_config_build","portable"):
            config=f1._build_config(kernel,initrd,config_path)

        docker_dir=w/"docker"; docker_dir.mkdir()
        with timer.stage("docker_local_image_build","venue"):
            docker_info=_prepare_docker(helper_bin,docker_dir)
        if not docker_info.get("ok"):
            return {"schema":SCHEMA,"result":{"classification":"SETUP_REQUIRED","reason":docker_info.get("reason")}}

        conditions=[]
        for kind in ("firecracker_only","native_cpu","docker_cpu"):
            with timer.stage(f"condition_{kind}","portable"):
                conditions.append(_run_condition(kind,fc,config_path,expected,helper_bin,docker_info["tag"]))

        baseline=conditions[0]["vm_makespan_ms"]
        for condition in conditions:
            condition["vm_slowdown_vs_firecracker_only"]=round(condition["vm_makespan_ms"]/baseline,4) if baseline else None

        all_passed=all(condition["classification"]=="SUPPORTED" for condition in conditions)
        return {
            "schema":SCHEMA,
            "probe_version":PROBE_VERSION,
            "authority":"SemperSupra/agent-dispatch-private#280",
            "requested_label":label,
            "result":{"classification":"SUPPORTED" if all_passed else "PARTIAL","all_conditions_passed":all_passed},
            "fixed_capsule":{
                "n_vm":N_VM,
                "input_sha256":f3.sha256_bytes(data),
                "candidate_binary_sha256":f1._sha256(cand_bin),
                "guest_init_binary_sha256":f1._sha256(init_bin),
                "helper_binary_sha256":f1._sha256(helper_bin),
                "vmm_version":vm["version"],
                "kernel_version":km["kernel_version"],
                "machine":{"vcpu_count_per_vm":config["machine-config"]["vcpu_count"],"mem_size_mib_per_vm":config["machine-config"]["mem_size_mib"],"network_interfaces":0,"drives":0},
            },
            "conditions":conditions,
            "lifecycle_timing":timer.receipt(),
            "host_identity":{
                "cpu":p1._cpu_identity(),
                "image_os":os.environ.get("ImageOS"),
                "image_version":os.environ.get("ImageVersion"),
                "memory":p1._meminfo(),
            },
            "sovereign_transfer":{"portable_contract_depends_on_github_actions":False,"docker_image_source":"local FROM scratch; no network pull"},
        }


def main() -> int:
    p=argparse.ArgumentParser()
    p.add_argument("--label",required=True)
    p.add_argument("--out",type=pathlib.Path,required=True)
    a=p.parse_args(); a.out.parent.mkdir(parents=True,exist_ok=True)
    try:
        receipt=run_probe(a.label)
    except Exception as exc:
        receipt={"schema":SCHEMA,"result":{"classification":"HARNESS_FAILURE","reason":f"{type(exc).__name__}: {exc}"}}
    a.out.write_text(json.dumps(receipt,indent=2,sort_keys=True)+"\n")
    print(json.dumps(receipt,indent=2,sort_keys=True))
    return 0 if receipt["result"]["classification"] in {"SUPPORTED","PARTIAL"} else 1


if __name__=="__main__":
    raise SystemExit(main())
