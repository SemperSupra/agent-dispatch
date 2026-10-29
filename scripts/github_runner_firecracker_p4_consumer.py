#!/usr/bin/env python3
from __future__ import annotations
import argparse,json,pathlib,sys,tempfile,threading,time
sys.path.insert(0,str(pathlib.Path(__file__).resolve().parent))
import github_runner_firecracker_f0 as f0
import github_runner_firecracker_f1_boot as f1
import github_runner_firecracker_p3_same_host_handoff as p3
from firecracker_host_fingerprint import fingerprint,compare_for_initial_snapshot_restore
from firecracker_lifecycle_timing import LifecycleTimer

SCHEMA="firecracker-p4-consumer/v1"

def run(bundle:pathlib.Path)->dict:
    timer=LifecycleTimer()
    prod=json.loads((bundle/"producer.json").read_text())
    state=bundle/prod["snapshot"]["state_file"]
    mem=bundle/prod["snapshot"]["memory_file"]
    with timer.stage("bundle_hash_verify","portable"):
        sh, mh = p3._sha256(state), p3._sha256(mem)
    if sh!=prod["snapshot"]["state_sha256"] or mh!=prod["snapshot"]["memory_sha256"]:
        return {"schema":SCHEMA,"result":{"classification":"ORACLE_FAILURE","reason":"bundle digest mismatch"}}

    destfp=fingerprint()
    gate=compare_for_initial_snapshot_restore(prod["producer_host_fingerprint"],destfp)
    receipt={
        "schema":SCHEMA,
        "authority":"SemperSupra/agent-dispatch-private#280",
        "producer_host_fingerprint":prod["producer_host_fingerprint"],
        "destination_host_fingerprint":destfp,
        "compatibility":gate,
        "snapshot":{"state_sha256":sh,"memory_sha256":mh,"state_size_bytes":state.stat().st_size,"memory_size_bytes":mem.stat().st_size},
    }
    if not gate["compatible_for_initial_restore_attempt"]:
        receipt["result"]={"classification":"COMPATIBILITY_MISMATCH","restore_attempted":False}
        receipt["lifecycle_timing"]=timer.receipt()
        return receipt

    vm=f1._load_json(p3.VMM_MANIFEST)
    with tempfile.TemporaryDirectory(prefix="firecracker-p4c-") as td:
        w=pathlib.Path(td); archive=w/"fc.tgz"; extract=w/"vmm"; extract.mkdir(); sock=w/"dest.sock"
        with timer.stage("vmm_download_and_verify","venue"):
            vv=f1._download_and_verify(vm["archive_url"],vm["archive_sha256"],archive)
        if not vv["verified"] or vv["actual_sha256"]!=prod["portable"]["vmm_archive_sha256"]:
            receipt["result"]={"classification":"ORACLE_FAILURE","restore_attempted":False,"reason":"VMM identity mismatch"}
            receipt["lifecycle_timing"]=timer.receipt(); return receipt
        with timer.stage("vmm_extract","portable"):
            f0._safe_extract(archive,extract)
            fc=f1._find_firecracker(extract,vm["version"],vm["architecture"])

        lines=[]; stop=threading.Event()
        with timer.stage("destination_process_start","portable"):
            proc=p3._launch(fc,sock,None)
            reader=threading.Thread(target=p3._reader,args=(proc,lines,stop),daemon=True); reader.start()
            if not p3._wait_for_socket(sock,5):
                p3._terminate_group(proc)
                receipt["result"]={"classification":"HARNESS_FAILURE","restore_attempted":False,"reason":"API socket unavailable"}
                receipt["lifecycle_timing"]=timer.receipt(); return receipt

        with timer.stage("snapshot_load","portable"):
            load=p3._api(sock,"PUT","/snapshot/load",{
                "snapshot_path":str(state.resolve()),
                "mem_backend":{"backend_path":str(mem.resolve()),"backend_type":"File"},
                "track_dirty_pages":False,"resume_vm":False})
        if not load["ok"]:
            p3._terminate_group(proc); stop.set(); reader.join(timeout=1)
            receipt["result"]={"classification":"ORACLE_FAILURE","restore_attempted":True,"reason":"snapshot load failed"}
            receipt["api"]={"load":load}; receipt["lifecycle_timing"]=timer.receipt(); return receipt

        t=time.perf_counter()
        with timer.stage("resume_api","portable"):
            resume=p3._api(sock,"PATCH","/vm",{"state":"Resumed"})
        first=p3._wait_for_regex(lines,p3.HEARTBEAT_RE,5) if resume["ok"] else None
        if first: timer.add("resume_to_first_guest_output","portable",(time.perf_counter()-t)*1000,derived=True)
        try: rc=proc.wait(timeout=5)
        except Exception: rc=p3._terminate_group(proc)["return_code"]
        stop.set(); reader.join(timeout=1)

    hbs=p3._all_heartbeat_values(lines)
    done=[int(m.group(1)) for line in lines if (m:=p3.DONE_RE.search(line))]
    ready=any(p3.READY_RE.search(line) for line in lines)
    src=prod["result"]["source_last_heartbeat_counter"]
    dst=hbs[0] if hbs else None
    ok=bool(resume["ok"] and dst is not None and dst>src and not ready and done and max(done)==20 and rc==0)
    receipt.update({
        "result":{"classification":"SUPPORTED" if ok else "ORACLE_FAILURE","restore_attempted":True,"continuity_oracle_satisfied":ok,
                  "producer_last_counter":src,"destination_first_counter":dst,"destination_reemitted_ready":ready,
                  "destination_done_counter":max(done) if done else None,"destination_exit_code":rc},
        "api":{"load":load,"resume":resume},
        "lifecycle_timing":timer.receipt(),
        "sovereign_transfer":{"portable_contract_depends_on_github_actions":False,"artifact_transport_excluded_from_restore_timing":True},
    })
    return receipt

def main()->int:
    p=argparse.ArgumentParser(); p.add_argument("--bundle",type=pathlib.Path,required=True); p.add_argument("--out",type=pathlib.Path,required=True)
    a=p.parse_args(); a.out.parent.mkdir(parents=True,exist_ok=True)
    try:r=run(a.bundle)
    except Exception as e:r={"schema":SCHEMA,"result":{"classification":"HARNESS_FAILURE","reason":f"{type(e).__name__}: {e}"}}
    a.out.write_text(json.dumps(r,indent=2,sort_keys=True)+"\n"); print(json.dumps(r,indent=2,sort_keys=True))
    return 0 if r["result"]["classification"] in {"SUPPORTED","COMPATIBILITY_MISMATCH"} else 1

if __name__=="__main__": raise SystemExit(main())
