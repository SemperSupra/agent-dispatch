#!/usr/bin/env python3
"""R1b: matched Firecracker virtio-block bandwidth rate-limit qualification."""
from __future__ import annotations

import argparse, json, os, pathlib, platform, tempfile, threading, time, sys
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))

import github_runner_firecracker_f0 as f0
import github_runner_firecracker_f1_boot as f1
import github_runner_firecracker_f3_useful_work as f3
import github_runner_firecracker_p1_concurrency as p1
import github_runner_firecracker_r1_storage as r1
from firecracker_lifecycle_timing import LifecycleTimer

SCHEMA="firecracker-r1b-block-rate-limit/v1"
AUTHORITY="SemperSupra/agent-dispatch-private#287"
LIMIT_BPS=16*1024*1024

def _run_condition(*,name,fc,kernel,initrd,image,work,rate_limited):
    config_path=work/f"{name}.json"
    cfg=f1._build_config(kernel,initrd,config_path)
    cfg["machine-config"]["mem_size_mib"]=256
    drive={
        "drive_id":"scratch",
        "path_on_host":str(image.resolve()),
        "is_root_device":False,
        "is_read_only":False,
    }
    if rate_limited:
        drive["rate_limiter"]={
            "bandwidth":{
                "size":LIMIT_BPS,
                "one_time_burst":0,
                "refill_time":1000,
            }
        }
    cfg["drives"]=[drive]
    config_path.write_text(json.dumps(cfg,indent=2,sort_keys=True)+"\n")

    before_cpu=p1._cpu_ticks(); before_mem=p1._meminfo()
    stop=threading.Event(); sample={}
    monitor=threading.Thread(target=p1._monitor,args=(fc.name,stop,sample),daemon=True)
    monitor.start()
    started=time.perf_counter()
    execution=f3.run_vm(fc,config_path,{"bytes":0,"lines":0,"words":0,"fnv1a64":""},timeout_seconds=25)
    elapsed=round((time.perf_counter()-started)*1000.0,3)
    stop.set(); monitor.join(timeout=1.0)
    after_cpu=p1._cpu_ticks(); after_mem=p1._meminfo()

    output=execution.get("output_tail","")
    m=r1.RESULT_RE.search(output)
    err=r1.ERROR_RE.search(output)
    observed=None
    if m:
        observed={
            "bytes":int(m.group(1)),
            "write_fsync_ns":int(m.group(2)),
            "read_ns":int(m.group(3)),
            "expected_checksum":int(m.group(4)),
            "observed_checksum":int(m.group(5)),
        }
    guest_ok=bool(observed) and (
        observed["bytes"]==r1.BYTES
        and observed["expected_checksum"]==observed["observed_checksum"]
        and observed["write_fsync_ns"]>0
        and observed["read_ns"]>0
        and execution.get("clean_vmm_exit_observed")
    )
    persisted=r1._post_vm_ext4(image)
    oracle=guest_ok and persisted["ok"]
    return {
        "name":name,
        "rate_limited":rate_limited,
        "classification":"SUPPORTED" if oracle else "ORACLE_FAILURE",
        "oracle_satisfied":oracle,
        "elapsed_ms":elapsed,
        "observed":observed,
        "guest_error_code":int(err.group(1)) if err else None,
        "post_vm_ext4":persisted,
        "host":{
            "cpu_busy_percent":p1._cpu_busy_percent(before_cpu,after_cpu),
            "memory_before":before_mem,
            "memory_after":after_mem,
            **sample,
        },
        "output_tail":output[-5000:],
    }

def run_probe(label):
    timer=LifecycleTimer()
    if platform.system()!="Linux" or platform.machine() not in {"x86_64","amd64"}:
        return {"schema":SCHEMA,"authority":AUTHORITY,"result":{"classification":"SETUP_REQUIRED"}}
    vm=f1._load_json(f3.VMM_MANIFEST); km=f1._load_json(f3.KERNEL_MANIFEST)
    with tempfile.TemporaryDirectory(prefix="firecracker-r1b-") as td:
        w=pathlib.Path(td); archive=w/"firecracker.tgz"; extract=w/"vmm"; extract.mkdir()
        kernel=w/"vmlinux"; init_bin=w/"r1-init"; initrd=w/"r1-initrd.cpio"
        base_img=w/"base.ext4"; limit_img=w/"limited.ext4"

        with timer.stage("vmm_download_and_verify","venue"):
            vv=f1._download_and_verify(vm["archive_url"],vm["archive_sha256"],archive)
        with timer.stage("vmm_extract","portable"):
            f0._safe_extract(archive,extract); fc=f1._find_firecracker(extract,vm["version"],vm["architecture"])
        with timer.stage("kernel_download_and_verify","venue"):
            kv=f1._download_and_verify(km["kernel_url"],km["kernel_sha256"],kernel)
        with timer.stage("storage_probe_compile","portable"):
            pc=f1._compile_init(r1.PROBE_SOURCE,init_bin)
        if not all([vv["verified"],kv["verified"],pc["ok"]]):
            return {"schema":SCHEMA,"authority":AUTHORITY,"result":{"classification":"HARNESS_FAILURE"}}
        with timer.stage("initramfs_build","portable"):
            r1._build_initramfs(init_bin,initrd)
        with timer.stage("baseline_ext4_create","venue"):
            fs1=r1._make_ext4(base_img)
        with timer.stage("limited_ext4_create","venue"):
            fs2=r1._make_ext4(limit_img)
        if not fs1["ok"] or not fs2["ok"]:
            return {"schema":SCHEMA,"authority":AUTHORITY,"result":{"classification":"SETUP_REQUIRED","reason":"ext4 image setup failed"}}

        with timer.stage("baseline_storage","portable"):
            baseline=_run_condition(name="baseline",fc=fc,kernel=kernel,initrd=initrd,image=base_img,work=w,rate_limited=False)
        with timer.stage("limited_storage","portable"):
            limited=_run_condition(name="limited",fc=fc,kernel=kernel,initrd=initrd,image=limit_img,work=w,rate_limited=True)

        b=(baseline.get("observed") or {}).get("write_fsync_ns")
        l=(limited.get("observed") or {}).get("write_fsync_ns")
        ratio=round(l/b,4) if b and l else None
        limit_effect=bool(
            baseline["oracle_satisfied"]
            and limited["oracle_satisfied"]
            and l is not None
            and l >= 2_500_000_000
            and ratio is not None
            and ratio >= 5.0
        )
        classification="SUPPORTED" if limit_effect else "ORACLE_FAILURE"
        return {
            "schema":SCHEMA,"authority":AUTHORITY,"requested_label":label,
            "result":{
                "classification":classification,
                "block_bandwidth_limit_enforced":limit_effect,
            },
            "rate_limit":{
                "bytes_per_second":LIMIT_BPS,
                "refill_time_ms":1000,
                "one_time_burst":0,
            },
            "baseline":baseline,
            "limited":limited,
            "comparison":{
                "baseline_write_fsync_ns":b,
                "limited_write_fsync_ns":l,
                "limited_over_baseline_write_ratio":ratio,
            },
            "lifecycle_timing":timer.receipt(),
            "next_gate":"R2 outbound-only network envelope if rate limiting passes.",
        }

def main():
    p=argparse.ArgumentParser(); p.add_argument("--label",required=True); p.add_argument("--out",type=pathlib.Path,required=True)
    a=p.parse_args(); a.out.parent.mkdir(parents=True,exist_ok=True)
    try: receipt=run_probe(a.label)
    except Exception as exc:
        receipt={"schema":SCHEMA,"authority":AUTHORITY,"result":{"classification":"HARNESS_FAILURE","reason":f"{type(exc).__name__}: {exc}"}}
    a.out.write_text(json.dumps(receipt,indent=2,sort_keys=True)+"\n"); print(json.dumps(receipt,indent=2,sort_keys=True))
    return 0 if receipt["result"]["classification"]=="SUPPORTED" else 1

if __name__=="__main__": raise SystemExit(main())
