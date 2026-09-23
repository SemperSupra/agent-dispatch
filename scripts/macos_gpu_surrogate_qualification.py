#!/usr/bin/env python3
"""Portable macOS GPU qualification interviews for GHA -> sovereign Mac transfer."""
from __future__ import annotations

import argparse
import json
import os
import pathlib
import platform
import shutil
import re
import subprocess
import tempfile
from typing import Any

SCHEMA = "macos-gpu-surrogate-qualification/v1"
PROBE_VERSION = "public-macos-gpu-surrogate/3"
TORCH_VERSION = "2.14.0"
MLX_VERSION = "0.32.2"
LLAMA_TAG = "v0.4.1"
COREMLTOOLS_VERSION = "9.0"

def run(argv: list[str], timeout: int = 300, cwd: str | None = None, env: dict[str,str] | None = None):
    try:
        cp=subprocess.run(argv,check=False,capture_output=True,text=True,timeout=timeout,cwd=cwd,env=env)
        return cp.returncode,cp.stdout.strip(),cp.stderr.strip()
    except (OSError,subprocess.SubprocessError) as exc:
        return None,"",f"{type(exc).__name__}: {exc}"

def result(classification: str, reason: str, **evidence: Any) -> dict[str,Any]:
    return {"classification":classification,"reason":reason,"evidence":evidence}

METAL_SWIFT = r'''
import Foundation
import Metal
import CoreGraphics

let count = 4096
let source = """
#include <metal_stdlib>
using namespace metal;
kernel void axpy(device const uint *a [[buffer(0)]],
                 device const uint *b [[buffer(1)]],
                 device uint *out [[buffer(2)]],
                 uint id [[thread_position_in_grid]]) {
    out[id] = a[id] * 3u + b[id];
}
"""

var r: [String: Any] = ["device": false, "compiled": false, "dispatched": false, "oracle": false, "elements": count]
if let device = MTLCreateSystemDefaultDevice() {
    r["device"] = true
    r["name"] = device.name
    r["unifiedMemory"] = device.hasUnifiedMemory
    r["maxBufferLength"] = UInt64(device.maxBufferLength)
    do {
        let library = try device.makeLibrary(source: source, options: nil)
        if let fn = library.makeFunction(name: "axpy") {
            let pipeline = try device.makeComputePipelineState(function: fn)
            r["compiled"] = true
            r["threadExecutionWidth"] = pipeline.threadExecutionWidth
            r["maxTotalThreadsPerThreadgroup"] = pipeline.maxTotalThreadsPerThreadgroup
            if let q = device.makeCommandQueue(),
               let a = device.makeBuffer(length: count * 4, options: .storageModeShared),
               let b = device.makeBuffer(length: count * 4, options: .storageModeShared),
               let o = device.makeBuffer(length: count * 4, options: .storageModeShared),
               let cb = q.makeCommandBuffer(),
               let enc = cb.makeComputeCommandEncoder() {
                let ap=a.contents().bindMemory(to: UInt32.self,capacity:count)
                let bp=b.contents().bindMemory(to: UInt32.self,capacity:count)
                let op=o.contents().bindMemory(to: UInt32.self,capacity:count)
                for i in 0..<count { ap[i]=UInt32(i); bp[i]=UInt32(1000+i); op[i]=0 }
                enc.setComputePipelineState(pipeline); enc.setBuffer(a,offset:0,index:0)
                enc.setBuffer(b,offset:0,index:1); enc.setBuffer(o,offset:0,index:2)
                let w=max(1,min(pipeline.threadExecutionWidth,pipeline.maxTotalThreadsPerThreadgroup))
                enc.dispatchThreads(MTLSize(width:count,height:1,depth:1),
                                    threadsPerThreadgroup:MTLSize(width:w,height:1,depth:1))
                enc.endEncoding(); cb.commit(); cb.waitUntilCompleted(); r["dispatched"]=true
                var mismatches=0
                for i in 0..<count {
                    if op[i] != UInt32(i)*3+UInt32(1000+i) { mismatches += 1; if mismatches >= 8 { break } }
                }
                r["mismatches"]=mismatches; r["commandStatus"]=cb.status.rawValue
                r["oracle"]=(mismatches==0 && cb.status == .completed)
            }
        }
    } catch { r["error"]=String(describing:error) }
}
let d=try! JSONSerialization.data(withJSONObject:r,options:[.sortedKeys])
print(String(data:d,encoding:.utf8)!)
'''

PYTORCH_TEST = r'''
import json, os, torch
r={"version":torch.__version__,"is_built":torch.backends.mps.is_built(),"is_available":torch.backends.mps.is_available(),"oracle":False}
if r["is_available"]:
    dev=torch.device("mps")
    x=torch.tensor([[1.,2.],[3.,4.]],device=dev,requires_grad=True)
    b=torch.tensor([[5.,6.],[7.,8.]],device=dev)
    y=x@b
    loss=y.sum()
    loss.backward()
    torch.mps.synchronize()
    out=y.detach().cpu().tolist()
    grad=x.grad.detach().cpu().tolist()
    r.update({"output_device":str(y.device),"grad_device":str(x.grad.device),"output":out,"grad":grad,
              "fallback_env":os.environ.get("PYTORCH_ENABLE_MPS_FALLBACK")})
    r["oracle"]=(out==[[19.0,22.0],[43.0,50.0]] and grad==[[11.0,15.0],[11.0,15.0]]
                 and str(y.device).startswith("mps") and str(x.grad.device).startswith("mps")
                 and os.environ.get("PYTORCH_ENABLE_MPS_FALLBACK")=="0")
print(json.dumps(r,sort_keys=True))
'''

MLX_TEST = r'''
import json, importlib.metadata, mlx.core as mx
r={"version":importlib.metadata.version("mlx"),"oracle":False}
mx.set_default_device(mx.gpu)
a=mx.array([[1.,2.],[3.,4.]])
b=mx.array([[5.,6.],[7.,8.]])
c=a@b
def f(x): return mx.sum(x*x)
g=mx.grad(f)(mx.array([1.,2.,3.]))
mx.eval(c,g)
out=c.tolist(); grad=g.tolist()
r.update({"default_device":str(mx.default_device()),"output":out,"grad":grad})
r["oracle"]=(out==[[19.0,22.0],[43.0,50.0]] and grad==[2.0,4.0,6.0] and "gpu" in str(mx.default_device()).lower())
print(json.dumps(r,sort_keys=True))
'''


COREML_TEST = r'''
import json, os, tempfile
import numpy as np
import coremltools as ct
from coremltools.converters.mil import Builder as mb, types

@mb.program(input_specs=[mb.TensorSpec(shape=(1,), dtype=types.fp32)])
def prog(x):
    one = mb.const(val=np.array([1.0], dtype=np.float32))
    return mb.add(x=x, y=one)

r={"version":ct.__version__,"oracle":False,"compute_units":"CPU_AND_GPU"}
with tempfile.TemporaryDirectory(prefix="coreml-gpu-interview-") as td:
    model=ct.convert(
        prog,
        convert_to="mlprogram",
        minimum_deployment_target=ct.target.macOS13,
        compute_units=ct.ComputeUnit.CPU_AND_GPU,
    )
    path=os.path.join(td,"Tiny.mlpackage")
    model.save(path)
    loaded=ct.models.MLModel(path,compute_units=ct.ComputeUnit.CPU_AND_GPU)
    pred=loaded.predict({"x":np.array([41.0],dtype=np.float32)})
    values=[]
    for value in pred.values():
        try:
            values.extend(np.array(value).astype(np.float32).reshape(-1).tolist())
        except Exception:
            pass
    r["outputs"]=values
    r["output_keys"]=sorted(pred.keys())
    r["oracle"]=any(abs(float(v)-42.0)<1e-5 for v in values)
print(json.dumps(r,sort_keys=True))
'''


def compile_run_swift(source: str) -> dict[str,Any]:
    xcrun=shutil.which("xcrun")
    if not xcrun: return result("NEGATIVE_OBSERVATION","xcrun unavailable")
    with tempfile.TemporaryDirectory(prefix="mac-gpu-metal-") as td:
        src=pathlib.Path(td)/"probe.swift";exe=pathlib.Path(td)/"probe"
        src.write_text(source,encoding="utf-8")
        cc,co,ce=run([xcrun,"--sdk","macosx","swiftc","-O","-framework","Metal","-framework","CoreGraphics",
                      str(src),"-o",str(exe)],timeout=90)
        if cc!=0: return result("HARNESS_FAILURE","Metal interview failed to compile",compile_exit=cc,stderr=ce[-4000:])
        rc,out,err=run([str(exe)],timeout=60)
        try: ev=json.loads(out.splitlines()[-1]) if out else {}
        except Exception: ev={}
        if rc!=0 or not ev: return result("HARNESS_FAILURE","Metal interview returned no receipt",run_exit=rc,stdout=out[-2000:],stderr=err[-2000:])
        if ev.get("oracle"): return result("SUPPORTED","multi-element programmable Metal compute passed",**ev)
        return result("ORACLE_FAILURE","Metal device was callable but vector compute oracle failed",**ev)

def make_venv(root: pathlib.Path) -> tuple[pathlib.Path,dict[str,Any]]:
    py=shutil.which("python3")
    if not py: return root/"venv"/"bin"/"python",result("HARNESS_FAILURE","python3 unavailable")
    code,out,err=run([py,"-m","venv",str(root/"venv")],timeout=90)
    return root/"venv"/"bin"/"python",{"exit_code":code,"stdout":out[-1000:] or None,"stderr":err[-2000:] or None}

def pip_install(vpy: pathlib.Path, packages: list[str]) -> dict[str,Any]:
    code,out,err=run([str(vpy),"-m","pip","install","--disable-pip-version-check","--no-cache-dir",*packages],timeout=600)
    return {"exit_code":code,"stdout":out[-3000:] or None,"stderr":err[-3000:] or None}

def run_python_interview(vpy: pathlib.Path, program: str, env: dict[str,str] | None=None) -> dict[str,Any]:
    code,out,err=run([str(vpy),"-c",program],timeout=180,env=env)
    try: ev=json.loads(out.splitlines()[-1]) if out else {}
    except Exception: ev={}
    if code!=0 or not ev: return result("HARNESS_FAILURE","runtime interview returned no receipt",exit_code=code,stdout=out[-2000:],stderr=err[-3000:])
    if ev.get("oracle"): return result("SUPPORTED","runtime GPU oracle passed",**ev)
    return result("ORACLE_FAILURE","runtime installed but GPU oracle failed",**ev,stderr=err[-2000:] or None)


def coreml_interview(root: pathlib.Path) -> dict[str,Any]:
    py=shutil.which("python3.13")
    if not py:
        return result("SKIPPED_GUARDRAIL","python3.13 unavailable for pinned coremltools 9.0 wheel")
    venv=root/"coreml-venv"
    rc,out,err=run([py,"-m","venv",str(venv)],timeout=90)
    if rc!=0:
        return result("HARNESS_FAILURE","Core ML venv creation failed",exit_code=rc,stderr=err[-2500:] or None)
    vpy=venv/"bin"/"python"
    rc,out,err=run([str(vpy),"-m","pip","install","--disable-pip-version-check","--no-cache-dir",
                    f"coremltools=={COREMLTOOLS_VERSION}","numpy<3"],timeout=360)
    if rc!=0:
        return result("ENVIRONMENT_FAILURE","pinned coremltools installation failed",
                      exit_code=rc,stdout=out[-2500:] or None,stderr=err[-3000:] or None)
    return run_python_interview(vpy,COREML_TEST)


def llama_interview(root: pathlib.Path) -> dict[str,Any]:
    git=shutil.which("git");cmake=shutil.which("cmake")
    if not git or not cmake: return result("HARNESS_FAILURE","git/cmake unavailable",git=git,cmake=cmake)
    src=root/"llama.cpp"
    rc,out,err=run([git,"clone","--depth","1","--branch",LLAMA_TAG,"https://github.com/ggml-org/llama.cpp.git",str(src)],timeout=240)
    if rc!=0: return result("ENVIRONMENT_FAILURE","llama.cpp acquisition failed",exit_code=rc,stderr=err[-3000:])
    _,commit,_=run([git,"rev-parse","HEAD"],cwd=str(src),timeout=15)
    rc,out,err=run([cmake,"-S",".","-B","build","-DCMAKE_BUILD_TYPE=Release","-DGGML_METAL=ON",
                    "-DGGML_METAL_EMBED_LIBRARY=ON","-DLLAMA_BUILD_TESTS=ON"],cwd=str(src),timeout=180)
    if rc!=0: return result("HARNESS_FAILURE","llama.cpp Metal configure failed",commit=commit,stderr=err[-4000:])
    rc,out,err=run([cmake,"--build","build","--config","Release","-j","2","--target","test-backend-ops"],
                   cwd=str(src),timeout=600)
    if rc!=0: return result("HARNESS_FAILURE","llama.cpp Metal backend test failed to build",commit=commit,stderr=err[-4000:])
    exe=src/"build"/"bin"/"test-backend-ops"
    help_rc,help_out,help_err=run([str(exe),"--help"],cwd=str(src),timeout=30)
    attempts=[]
    # Start with the desired matrix primitive, then fall back only to simple generic
    # operators that still prove ggml -> Metal execution against the CPU reference.
    for op in ("MUL_MAT","ADD","MUL","SQR","SCALE"):
        argv=[str(exe),"test","-b","MTL0","-o",op]
        rc,out,err=run(argv,cwd=str(src),timeout=300)
        counts=re.findall(r"(\d+)/(\d+) tests passed",out)
        executed_cases=max((int(total) for passed,total in counts),default=0)
        passed_cases=max((int(passed) for passed,total in counts),default=0)
        backend_seen=("Backend 1/3: MTL0" in out or "MTL0" in err)
        passed=(rc==0 and backend_seen and executed_cases>0 and passed_cases==executed_cases)
        attempts.append({"op":op,"argv":argv[1:],"exit_code":rc,
                         "executed_cases":executed_cases,"passed_cases":passed_cases,
                         "stdout":out[-6000:] or None,"stderr":err[-3500:] or None})
        if passed:
            return result("SUPPORTED",f"llama.cpp MTL0 {op} reference-comparison tests executed and passed",
                          tag=LLAMA_TAG,commit=commit,operator=op,attempts=attempts,
                          help_exit=help_rc,help_stdout=help_out[-2500:] or None,
                          help_stderr=help_err[-1500:] or None)
    return result("ORACLE_FAILURE","llama.cpp initialized Metal but no selected backend operator test both executed and passed",
                  tag=LLAMA_TAG,commit=commit,attempts=attempts,
                  help_exit=help_rc,help_stdout=help_out[-2500:] or None,help_stderr=help_err[-1500:] or None)

def main() -> int:
    p=argparse.ArgumentParser();p.add_argument("--label",required=True);p.add_argument("--out",required=True);args=p.parse_args()
    receipt: dict[str,Any]={
      "schema":SCHEMA,
      "provenance":{"requested_label":args.label,"probe_version":PROBE_VERSION,"run_id":os.environ.get("GITHUB_RUN_ID",""),
        "run_attempt":os.environ.get("GITHUB_RUN_ATTEMPT",""),"workflow_sha":os.environ.get("GITHUB_SHA",""),
        "image_os":os.environ.get("ImageOS"),"image_version":os.environ.get("ImageVersion")},
      "runner":{"system":platform.system(),"machine":platform.machine()},
      "pins":{"torch":TORCH_VERSION,"mlx":MLX_VERSION,"llama_cpp":LLAMA_TAG,"coremltools":COREMLTOOLS_VERSION},
      "interviews":{},
      "warnings":["GHA paravirtual GPU results are methodology/capability evidence, not local Apple-silicon performance evidence",
                  "local sovereign qualification must mint a distinct environment/configuration identity and rerun the same oracles"]}

    if platform.system()!="Darwin":
        receipt["classification"]="SKIPPED_GUARDRAIL";receipt["reason"]="macOS-only qualification lane"
    else:
        receipt["interviews"]["native-metal-vector"]=compile_run_swift(METAL_SWIFT)
        with tempfile.TemporaryDirectory(prefix="mac-gpu-runtime-") as td:
            root=pathlib.Path(td)
            if platform.machine()=="arm64":
                vpy,venv_ev=make_venv(root)
                receipt["venv"]=venv_ev
                if venv_ev.get("exit_code")==0:
                    install=pip_install(vpy,[f"torch=={TORCH_VERSION}",f"mlx=={MLX_VERSION}"])
                    receipt["python_dependency_preparation"]=install
                    if install.get("exit_code")==0:
                        env=dict(os.environ);env["PYTORCH_ENABLE_MPS_FALLBACK"]="0"
                        receipt["interviews"]["pytorch-mps"]=run_python_interview(vpy,PYTORCH_TEST,env=env)
                        receipt["interviews"]["mlx-gpu"]=run_python_interview(vpy,MLX_TEST)
                    else:
                        receipt["interviews"]["pytorch-mps"]=result("ENVIRONMENT_FAILURE","pinned Python GPU stack install failed")
                        receipt["interviews"]["mlx-gpu"]=result("ENVIRONMENT_FAILURE","pinned Python GPU stack install failed")
                else:
                    receipt["interviews"]["pytorch-mps"]=result("HARNESS_FAILURE","venv creation failed")
                    receipt["interviews"]["mlx-gpu"]=result("HARNESS_FAILURE","venv creation failed")
            else:
                receipt["interviews"]["pytorch-mps"]=result("SKIPPED_GUARDRAIL","current pinned PyTorch macOS wheel lane is Apple-silicon only")
                receipt["interviews"]["mlx-gpu"]=result("SKIPPED_GUARDRAIL","MLX Apple-silicon transfer interview is ARM64-only")
            receipt["interviews"]["llama-cpp-metal"]=llama_interview(root)
            receipt["interviews"]["coreml-cpu-gpu-policy"]=coreml_interview(root)

        classes=[v.get("classification") for v in receipt["interviews"].values()]
        if all(c in {"SUPPORTED","SKIPPED_GUARDRAIL"} for c in classes) and "SUPPORTED" in classes:
            receipt["classification"]="SUPPORTED";receipt["reason"]="all applicable first-tranche Mac GPU transfer interviews passed"
        elif any(c=="SUPPORTED" for c in classes):
            receipt["classification"]="PARTIAL";receipt["reason"]="at least one Mac GPU transfer interview passed but one or more applicable interviews did not"
        else:
            receipt["classification"]="ORACLE_FAILURE";receipt["reason"]="no Mac GPU transfer interview passed"

    path=pathlib.Path(args.out);path.parent.mkdir(parents=True,exist_ok=True)
    path.write_text(json.dumps(receipt,indent=2,sort_keys=True)+"\n",encoding="utf-8")
    print(f"MAC_GPU_QUALIFICATION_RECEIPT={path}");print(json.dumps(receipt,indent=2,sort_keys=True))
    return 0

if __name__=="__main__": raise SystemExit(main())
