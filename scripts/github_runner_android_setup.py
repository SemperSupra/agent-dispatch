#!/usr/bin/env python3
"""Read-only Android SDK setup inventory for x64 Ubuntu hosted runners."""
from __future__ import annotations
import argparse, json, os, pathlib, platform, re, subprocess

def _run(argv, timeout=10):
    try:
        cp=subprocess.run(argv,check=False,capture_output=True,text=True,timeout=timeout)
        return cp.returncode,cp.stdout.strip(),cp.stderr.strip()
    except Exception as exc:
        return None,"",str(exc)

def _children(root:pathlib.Path,prefix:str=""):
    if not root.is_dir(): return []
    return sorted(p.name for p in root.iterdir() if p.is_dir() and (not prefix or p.name.startswith(prefix)))

def _system_images(sdk:pathlib.Path):
    root=sdk/"system-images"; out=[]
    if not root.is_dir(): return out
    for abi in root.glob("android-*/*/*"):
        if not abi.is_dir(): continue
        rel=abi.relative_to(root).parts
        if len(rel)==3:
            out.append({
                "package":"system-images;"+";".join(rel),
                "api":rel[0],
                "tag":rel[1],
                "abi":rel[2],
            })
    return sorted(out,key=lambda x:x["package"])

def inventory(label:str):
    receipt={
        "schema":"github-runner-android-setup-inventory/v1",
        "provenance":{
            "requested_label":label,
            "workflow_sha":os.environ.get("GITHUB_SHA",""),
            "run_id":os.environ.get("GITHUB_RUN_ID",""),
            "run_attempt":os.environ.get("GITHUB_RUN_ATTEMPT",""),
            "image_os":os.environ.get("ImageOS"),
            "image_version":os.environ.get("ImageVersion"),
        },
        "runner":{"system":platform.system(),"machine":platform.machine()},
        "result":{"classification":"INCONCLUSIVE","reason":"not inspected","evidence":{}},
        "warnings":["read-only inventory; no SDK package installation or download was attempted"],
    }
    if platform.system()!="Linux" or platform.machine() not in {"x86_64","amd64"}:
        receipt["result"]={"classification":"SKIPPED_GUARDRAIL","reason":"x86_64 Linux-only inventory","evidence":{}}
        return receipt
    raw=os.environ.get("ANDROID_HOME") or os.environ.get("ANDROID_SDK_ROOT") or "/usr/local/lib/android/sdk"
    sdk=pathlib.Path(raw)
    if not sdk.is_dir():
        receipt["result"]={"classification":"NEGATIVE_OBSERVATION","reason":"Android SDK root absent","evidence":{"sdk_root":raw}}
        return receipt
    paths={
        "sdkmanager":sdk/"cmdline-tools"/"latest"/"bin"/"sdkmanager",
        "avdmanager":sdk/"cmdline-tools"/"latest"/"bin"/"avdmanager",
        "adb":sdk/"platform-tools"/"adb",
        "emulator":sdk/"emulator"/"emulator",
    }
    versions={}
    if paths["sdkmanager"].exists():
        code,out,err=_run([str(paths["sdkmanager"]),"--version"])
        versions["sdkmanager"]={"exit_code":code,"value":out or None,"stderr":err[:500] or None}
    if paths["adb"].exists():
        code,out,err=_run([str(paths["adb"]),"version"])
        versions["adb"]={"exit_code":code,"value":out.splitlines()[0] if out else None,"stderr":err[:500] or None}
    images=_system_images(sdk)
    x86=[x for x in images if x["abi"] in {"x86_64","x86"}]
    missing=[]
    if not paths["emulator"].exists(): missing.append("emulator")
    if not paths["adb"].exists(): missing.append("platform-tools/adb")
    if not paths["avdmanager"].exists(): missing.append("avdmanager")
    if not x86: missing.append("x86_64-system-image")
    evidence={
        "sdk_root":str(sdk),
        "paths":{k:{"path":str(v),"present":v.exists()} for k,v in paths.items()},
        "versions":versions,
        "build_tools":_children(sdk/"build-tools"),
        "platforms":_children(sdk/"platforms","android-"),
        "system_images":images,
        "x86_system_images":x86,
        "setup_required_components":missing,
    }
    if missing:
        receipt["result"]={"classification":"SKIPPED_GUARDRAIL",
                           "reason":"Android emulator workload requires additional SDK components",
                           "evidence":evidence}
    else:
        receipt["result"]={"classification":"SUPPORTED",
                           "reason":"preinstalled SDK contains emulator, adb, avdmanager, and x86 system image",
                           "evidence":evidence}
    return receipt

def main():
    p=argparse.ArgumentParser(); p.add_argument("--label",required=True); p.add_argument("--out",required=True)
    a=p.parse_args(); r=inventory(a.label)
    path=pathlib.Path(a.out); path.parent.mkdir(parents=True,exist_ok=True)
    path.write_text(json.dumps(r,indent=2,sort_keys=True)+"\n",encoding="utf-8")
    print("ANDROID_SETUP_RECEIPT="+str(path)); print(json.dumps(r,indent=2,sort_keys=True))
    return 0
if __name__=="__main__": raise SystemExit(main())
