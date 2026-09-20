#!/usr/bin/env python3
"""Demand-driven lightweight/native-build workload qualifications."""
from __future__ import annotations
import argparse, hashlib, json, os, pathlib, platform, shutil, subprocess, tempfile, time

def run(argv, timeout=60, cwd=None):
    try:
        cp=subprocess.run(argv,check=False,capture_output=True,text=True,timeout=timeout,cwd=cwd)
        return cp.returncode,cp.stdout.strip(),cp.stderr.strip()
    except subprocess.TimeoutExpired:
        return None,"",f"timeout after {timeout}s"
    except Exception as exc:
        return None,"",str(exc)

def base(label, workload):
    return {
      "schema":"github-runner-placement-workload/v1",
      "provenance":{
        "requested_label":label,"workflow_sha":os.environ.get("GITHUB_SHA",""),
        "run_id":os.environ.get("GITHUB_RUN_ID",""),"run_attempt":os.environ.get("GITHUB_RUN_ATTEMPT",""),
        "image_os":os.environ.get("ImageOS"),"image_version":os.environ.get("ImageVersion"),
      },
      "runner":{"system":platform.system(),"machine":platform.machine(),"runner_arch":os.environ.get("RUNNER_ARCH")},
      "workload":{"id":workload},
      "result":{"classification":"INCONCLUSIVE","passed":False,"reason":"not executed","evidence":{}},
      "warnings":["workload qualification is exact-workload/exact-image evidence, not a runner ranking"]
    }

def finish(r, classification, passed, reason, evidence):
    r["result"]={"classification":classification,"passed":passed,"reason":reason,"evidence":evidence}
    return r

def slim_contract(label):
    r=base(label,"agent-dispatch-sealed-public-execution-contract-native")
    if label!="ubuntu-slim" or platform.system()!="Linux":
        return finish(r,"SKIPPED_GUARDRAIL",False,"workload is pinned to ubuntu-slim",{})
    py=shutil.which("python3")
    test=pathlib.Path("tests/test_sealed_public_execution.py")
    if not py or not test.exists():
        return finish(r,"SKIPPED_GUARDRAIL",False,"python/test entry gate missing",
                      {"python3":py,"test_present":test.exists()})
    started=time.monotonic()
    code,out,err=run([py,"-m","unittest","-v",str(test)],timeout=90)
    elapsed=time.monotonic()-started
    return finish(r,"SUPPORTED" if code==0 else "ORACLE_FAILURE",code==0,
                  "production Agent Dispatch contract suite passed natively on ubuntu-slim"
                  if code==0 else "production Agent Dispatch contract suite failed on ubuntu-slim",
                  {"exit_code":code,"elapsed_seconds":round(elapsed,3),
                   "python":py,"stdout_tail":out[-1500:] if out else None,
                   "stderr_tail":err[-1500:] if err else None})

C_SOURCE=r"""
#include <stdint.h>
#include <stdio.h>
int main(void) {
    uint64_t nonce = UINT64_C(0x5a17c0de5a17c0de);
    printf("ARM_NATIVE_NONCE=%016llx\n",(unsigned long long)nonce);
    return nonce == UINT64_C(0x5a17c0de5a17c0de) ? 0 : 3;
}
"""

def arm_native_artifact(label):
    r=base(label,"native-arm64-c-artifact")
    if platform.system()!="Linux" or platform.machine() not in {"aarch64","arm64"}:
        return finish(r,"SKIPPED_GUARDRAIL",False,"native ARM64 workload requires ARM64 Linux",{})
    cc=shutil.which("cc") or shutil.which("gcc") or shutil.which("clang")
    file_cmd=shutil.which("file")
    if not cc or not file_cmd:
        return finish(r,"SKIPPED_GUARDRAIL",False,"native compiler/file utility missing",
                      {"compiler":cc,"file":file_cmd})
    with tempfile.TemporaryDirectory(prefix="runner-arm-build-") as td:
        root=pathlib.Path(td); src=root/"nonce.c"; exe=root/"nonce"
        src.write_text(C_SOURCE,encoding="utf-8")
        started=time.monotonic()
        bc,bout,berr=run([cc,"-O2","-Wall","-Wextra","-Werror",str(src),"-o",str(exe)],timeout=60)
        build_s=time.monotonic()-started
        if bc!=0 or not exe.exists():
            return finish(r,"ORACLE_FAILURE",False,"native ARM64 compile/link failed",
                          {"compiler":cc,"exit_code":bc,"stderr":berr[-1500:] if berr else None})
        fc,fout,ferr=run([file_cmd,str(exe)],timeout=10)
        rc,rout,rerr=run([str(exe)],timeout=10)
        blob=exe.read_bytes()
        sha=hashlib.sha256(blob).hexdigest()
    arch_ok=("aarch64" in fout.lower() or "arm64" in fout.lower() or "arm aarch64" in fout.lower())
    nonce_ok="ARM_NATIVE_NONCE=5a17c0de5a17c0de" in rout
    passed=bc==0 and fc==0 and rc==0 and arch_ok and nonce_ok
    return finish(r,"SUPPORTED" if passed else "ORACLE_FAILURE",passed,
                  "compiled, linked, identified, and executed native ARM64 artifact" if passed
                  else "native ARM64 artifact oracle failed",
                  {"compiler":cc,"build_elapsed_seconds":round(build_s,3),
                   "file_output":fout[:1000] if fout else None,"run_exit":rc,
                   "nonce_match":nonce_ok,"sha256":sha,"artifact_bytes":len(blob),
                   "stderr":"\n".join(x for x in (berr,ferr,rerr) if x)[-1500:] or None})

WORKLOADS={"slim-contract":slim_contract,"arm-native-artifact":arm_native_artifact}

def main():
    p=argparse.ArgumentParser();p.add_argument("--label",required=True)
    p.add_argument("--workload",choices=sorted(WORKLOADS),required=True);p.add_argument("--out",required=True)
    a=p.parse_args();r=WORKLOADS[a.workload](a.label)
    out=pathlib.Path(a.out);out.parent.mkdir(parents=True,exist_ok=True)
    out.write_text(json.dumps(r,indent=2,sort_keys=True)+"\n",encoding="utf-8")
    print("PLACEMENT_WORKLOAD_RECEIPT="+str(out));print(json.dumps(r,indent=2,sort_keys=True))
    return 0

if __name__=="__main__":raise SystemExit(main())
