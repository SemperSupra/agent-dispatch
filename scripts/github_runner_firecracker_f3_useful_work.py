#!/usr/bin/env python3
from __future__ import annotations

import argparse
import hashlib
import json
import os
import pathlib
import platform
import re
import shutil
import stat
import sys
import tempfile

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
import github_runner_firecracker_f0 as f0
import github_runner_firecracker_f1_boot as f1
import firecracker_execution_adapter as exec_adapter
from firecracker_lifecycle_timing import LifecycleTimer

VMM_MANIFEST = pathlib.Path("experiments/firecracker/firecracker-v1.17.0-x86_64.json")
KERNEL_MANIFEST = pathlib.Path("experiments/firecracker/guest-kernel-6.18.48-x86_64.json")
INIT_SOURCE = pathlib.Path("experiments/firecracker/guest/f3-init-x86_64.c")
CANDIDATE_SOURCE = pathlib.Path("experiments/firecracker/guest/f3-candidate-x86_64.c")
DEFAULT_INPUT = pathlib.Path("experiments/firecracker/guest/f3-input.txt")
RESULT_RE = re.compile(r"FIRECRACKER_F3_CANDIDATE_RESULT bytes=(\d+) lines=(\d+) words=(\d+) fnv1a64=([0-9a-f]{16}) work_ns=(\d+)")
EXIT_RE = re.compile(r"FIRECRACKER_F3_EXIT code=(\d+) elapsed_ns=(\d+)")
INIT_RE = re.compile(r"\[\s*([0-9]+\.[0-9]+)\]\s+Run /init as init process")


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def fnv1a64(data: bytes) -> int:
    value = 14695981039346656037
    for byte in data:
        value ^= byte
        value = (value * 1099511628211) & 0xFFFFFFFFFFFFFFFF
    return value


def word_count(data: bytes) -> int:
    ws = b" \n\t\r\f\v"
    count = 0
    inside = False
    for byte in data:
        if byte in ws:
            inside = False
        elif not inside:
            count += 1
            inside = True
    return count


def expected_result(data: bytes) -> dict:
    return {
        "bytes": len(data),
        "lines": data.count(b"\n"),
        "words": word_count(data),
        "fnv1a64": f"{fnv1a64(data):016x}",
    }


def build_initramfs(init_bin: pathlib.Path, candidate_bin: pathlib.Path, data: bytes, out: pathlib.Path) -> None:
    payload = b"".join([
        f1._newc_entry(".", mode=stat.S_IFDIR | 0o755, ino=1, nlink=2),
        f1._newc_entry("dev", mode=stat.S_IFDIR | 0o755, ino=2, nlink=2),
        f1._newc_entry("dev/console", mode=stat.S_IFCHR | 0o600, ino=3, rdevmajor=5, rdevminor=1),
        f1._newc_entry("work", mode=stat.S_IFDIR | 0o555, ino=4, nlink=2),
        f1._newc_entry("work/input.txt", mode=stat.S_IFREG | 0o444, data=data, ino=5),
        f1._newc_entry("work/candidate", mode=stat.S_IFREG | 0o555, data=candidate_bin.read_bytes(), ino=6),
        f1._newc_entry("init", mode=stat.S_IFREG | 0o755, data=init_bin.read_bytes(), ino=7),
        f1._newc_entry("TRAILER!!!", mode=0, ino=8),
    ])
    out.write_bytes(payload)


def run_vm(binary: pathlib.Path, config: pathlib.Path, expected: dict) -> dict:
    timeout = shutil.which("timeout")
    access = exec_adapter.select_kvm_access()
    if not timeout or access.get("classification") != "SUPPORTED":
        return {
            "classification": "SETUP_REQUIRED",
            "ok": False,
            "reason": "timeout or qualified KVM execution boundary unavailable",
            "kvm_access": access,
        }

    command = exec_adapter.privileged_command(
        [timeout, "--signal=TERM", "--kill-after=2s", "20s",
         str(binary.resolve()), "--no-api", "--config-file", str(config.resolve())],
        access,
    )
    code, out, err = f0._run(command, timeout=25)
    combined = "\n".join(x for x in (out, err) if x)
    rm = RESULT_RE.search(combined)
    em = EXIT_RE.search(combined)
    im = INIT_RE.search(combined)

    observed = None
    if rm:
        observed = {
            "bytes": int(rm.group(1)),
            "lines": int(rm.group(2)),
            "words": int(rm.group(3)),
            "fnv1a64": rm.group(4),
            "work_ns": int(rm.group(5)),
        }
    exit_info = None
    if em:
        exit_info = {"exit_code": int(em.group(1)), "elapsed_ns": int(em.group(2))}

    result_ok = bool(observed) and all(observed[k] == expected[k] for k in ("bytes","lines","words","fnv1a64"))
    exit_ok = bool(exit_info) and exit_info["exit_code"] == 0
    vmm_ok = code == 0 and "Firecracker exiting successfully" in combined
    ok = result_ok and exit_ok and vmm_ok
    return {
        "classification": "SUPPORTED" if ok else "ORACLE_FAILURE",
        "ok": ok,
        "reason": "fixed guest candidate completed and reconciled" if ok else "F3 guest/result oracle failed",
        "candidate_result": observed,
        "candidate_exit": exit_info,
        "kernel_to_init_ms": float(im.group(1))*1000.0 if im else None,
        "clean_vmm_exit_observed": vmm_ok,
        "output_tail": combined[-8000:],
        "kvm_access_mode": access.get("mode"),
    }


def run_probe(label: str, input_path: pathlib.Path) -> dict:
    timer = LifecycleTimer()
    if platform.system() != "Linux" or platform.machine() not in {"x86_64","amd64"}:
        return {"schema":"firecracker-f3-useful-work-receipt/v1","result":{"classification":"SETUP_REQUIRED"}}

    data = input_path.read_bytes()
    if not data or len(data) > 4096:
        return {"schema":"firecracker-f3-useful-work-receipt/v1","result":{"classification":"SKIPPED_GUARDRAIL"}}

    expected = expected_result(data)
    vm = f1._load_json(VMM_MANIFEST)
    km = f1._load_json(KERNEL_MANIFEST)

    with tempfile.TemporaryDirectory(prefix="firecracker-f3-") as td:
        w = pathlib.Path(td)
        archive, kernel = w/"firecracker.tgz", w/"vmlinux"
        extract = w/"vmm"; extract.mkdir()
        init_bin, cand_bin, initrd, config_path = w/"init", w/"candidate", w/"initrd.cpio", w/"vm-config.json"

        with timer.stage("vmm_download_and_verify","venue"):
            vv = f1._download_and_verify(vm["archive_url"], vm["archive_sha256"], archive)
        with timer.stage("vmm_extract","portable"):
            f0._safe_extract(archive, extract)
            fc = f1._find_firecracker(extract, vm["version"], vm["architecture"])
        with timer.stage("kernel_download_and_verify","venue"):
            kv = f1._download_and_verify(km["kernel_url"], km["kernel_sha256"], kernel)
        with timer.stage("candidate_compile","portable"):
            cc = f1._compile_init(CANDIDATE_SOURCE, cand_bin)
        with timer.stage("guest_init_compile","portable"):
            ic = f1._compile_init(INIT_SOURCE, init_bin)
        if not vv["verified"] or not kv["verified"] or not cc["ok"] or not ic["ok"]:
            return {"schema":"firecracker-f3-useful-work-receipt/v1","result":{"classification":"HARNESS_FAILURE"}}
        with timer.stage("capsule_initramfs_build","portable"):
            build_initramfs(init_bin, cand_bin, data, initrd)
        with timer.stage("vm_config_build","portable"):
            config = f1._build_config(kernel, initrd, config_path)
        with timer.stage("firecracker_guest_lifecycle","portable"):
            execution = run_vm(fc, config_path, expected)

        cr = execution.get("candidate_result") or {}
        ce = execution.get("candidate_exit") or {}
        if cr.get("work_ns") is not None:
            timer.add("guest_candidate_work","portable",cr["work_ns"]/1_000_000.0,derived=True)
        if ce.get("elapsed_ns") is not None:
            timer.add("guest_candidate_spawn_to_reap","portable",ce["elapsed_ns"]/1_000_000.0,derived=True)
        if execution.get("kernel_to_init_ms") is not None:
            timer.add("guest_kernel_to_init","portable",execution["kernel_to_init_ms"],derived=True)

        return {
            "schema":"firecracker-f3-useful-work-receipt/v1",
            "probe_version":"firecracker-f3-useful-work/1",
            "authority":"SemperSupra/agent-dispatch-private#280",
            "requested_label":label,
            "result":{
                "classification":execution["classification"],
                "reason":execution["reason"],
                "useful_work_oracle_satisfied":execution["ok"],
            },
            "portable":{
                "input":{"size_bytes":len(data),"sha256":sha256_bytes(data)},
                "candidate":{"source":str(CANDIDATE_SOURCE),"binary_sha256":f1._sha256(cand_bin),"expected":expected,"observed":cr,"exit":ce},
                "guest_init":{"source":str(INIT_SOURCE),"binary_sha256":f1._sha256(init_bin),"initrd_sha256":f1._sha256(initrd)},
                "vmm":{"version":vm["version"],"archive_sha256":vv["actual_sha256"]},
                "kernel":{"version":km["kernel_version"],"sha256":kv["actual_sha256"]},
                "machine":{"vcpu_count":config["machine-config"]["vcpu_count"],"mem_size_mib":config["machine-config"]["mem_size_mib"],"drives":0,"network_interfaces":0},
            },
            "execution_oracle":execution,
            "lifecycle_timing":timer.receipt(),
            "venue_adapter":{"venue":"github-actions" if os.environ.get("GITHUB_ACTIONS")=="true" else "other","image_os":os.environ.get("ImageOS"),"image_version":os.environ.get("ImageVersion")},
            "sovereign_transfer":{"portable_contract_depends_on_github_actions":False,"baseline_role":"fixed workload for later topology experiments"},
        }


def main() -> int:
    p=argparse.ArgumentParser()
    p.add_argument("--label",required=True)
    p.add_argument("--input",type=pathlib.Path,default=DEFAULT_INPUT)
    p.add_argument("--out",type=pathlib.Path,required=True)
    a=p.parse_args()
    a.out.parent.mkdir(parents=True,exist_ok=True)
    try:
        receipt=run_probe(a.label,a.input)
    except Exception as exc:
        receipt={"schema":"firecracker-f3-useful-work-receipt/v1","result":{"classification":"HARNESS_FAILURE","reason":f"{type(exc).__name__}: {exc}"}}
    a.out.write_text(json.dumps(receipt,indent=2,sort_keys=True)+"\n")
    print(json.dumps(receipt,indent=2,sort_keys=True))
    return 0 if receipt["result"]["classification"]=="SUPPORTED" else 1


if __name__=="__main__":
    raise SystemExit(main())
