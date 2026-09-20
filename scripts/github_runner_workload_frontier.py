#!/usr/bin/env python3
"""Representative workload qualification at the current runner-placement frontier.

No packages or SDK/runtime images are downloaded. Each workload consumes only
tooling already present on the hosted image and emits a public-safe receipt.
"""
from __future__ import annotations

import argparse
import json
import os
import pathlib
import platform
import re
import shutil
import subprocess
import tempfile
import time
import uuid
from typing import Any

SCHEMA="github-runner-frontier-workload/v1"
PROBE_VERSION="frontier-workload/1"

def _run(argv:list[str], *, timeout:int=30, env:dict[str,str]|None=None,
         stdin:str|None=None)->tuple[int|None,str,str]:
    try:
        cp=subprocess.run(argv,check=False,capture_output=True,text=True,
                          timeout=timeout,env=env,input=stdin)
        return cp.returncode,cp.stdout.strip(),cp.stderr.strip()
    except subprocess.TimeoutExpired:
        return None,"",f"timeout after {timeout}s"
    except (OSError,subprocess.SubprocessError) as exc:
        return None,"",str(exc)

def _base(label:str,workload:str)->dict[str,Any]:
    return {
        "schema":SCHEMA,
        "provenance":{
            "requested_label":label,
            "workflow_sha":os.environ.get("GITHUB_SHA",""),
            "run_id":os.environ.get("GITHUB_RUN_ID",""),
            "run_attempt":os.environ.get("GITHUB_RUN_ATTEMPT",""),
            "image_os":os.environ.get("ImageOS"),
            "image_version":os.environ.get("ImageVersion"),
            "probe_version":PROBE_VERSION,
        },
        "runner":{
            "system":platform.system(),
            "machine":platform.machine(),
            "runner_arch":os.environ.get("RUNNER_ARCH"),
        },
        "workload":{"id":workload},
        "result":{
            "classification":"INCONCLUSIVE",
            "passed":False,
            "reason":"not executed",
            "evidence":{},
        },
        "warnings":[
            "workload qualification is specific to the named workload and exact image observation",
            "no scalar runner ranking is implied",
        ],
    }

def _finish(receipt:dict[str,Any],classification:str,passed:bool,reason:str,
            evidence:dict[str,Any])->dict[str,Any]:
    receipt["result"]={
        "classification":classification,
        "passed":passed,
        "reason":reason,
        "evidence":evidence,
    }
    return receipt

def _sdk_root()->pathlib.Path|None:
    for value in (os.environ.get("ANDROID_HOME"),os.environ.get("ANDROID_SDK_ROOT"),
                  "/usr/local/lib/android/sdk"):
        if value:
            p=pathlib.Path(value)
            if p.exists():
                return p
    return None

def _installed_x86_system_images(sdk:pathlib.Path)->list[tuple[tuple[int,...],str,pathlib.Path]]:
    root=sdk/"system-images"
    found=[]
    if not root.is_dir():
        return found
    for abi in root.glob("android-*/*/x86_64"):
        try:
            api=tuple(int(x) for x in re.findall(r"\d+",abi.parents[1].name))
            tag=abi.parent.name
            package=f"system-images;{abi.parents[1].name};{tag};x86_64"
            found.append((api,package,abi))
        except Exception:
            continue
    return sorted(found,key=lambda x:x[0])

def qualify_android_emulator(label:str)->dict[str,Any]:
    r=_base(label,"android-emulator-kvm-boot")
    if platform.system()!="Linux" or platform.machine() not in {"x86_64","amd64"}:
        return _finish(r,"SKIPPED_GUARDRAIL",False,"Android emulator workload is x86_64 Linux-only",{})
    sdk=_sdk_root()
    if not sdk:
        return _finish(r,"SKIPPED_GUARDRAIL",False,"Android SDK root not present",{})
    emulator=sdk/"emulator"/"emulator"
    adb=sdk/"platform-tools"/"adb"
    avdmanager=sdk/"cmdline-tools"/"latest"/"bin"/"avdmanager"
    missing=[str(p) for p in (emulator,adb,avdmanager) if not p.exists()]
    if missing:
        return _finish(r,"SKIPPED_GUARDRAIL",False,"preinstalled Android emulator toolchain incomplete",
                       {"missing":missing,"sdk_root":str(sdk)})
    images=_installed_x86_system_images(sdk)
    if not images:
        return _finish(r,"SKIPPED_GUARDRAIL",False,
                       "no preinstalled x86_64 Android system image; downloads intentionally disabled",
                       {"sdk_root":str(sdk)})
    _api,package,_path=images[-1]
    sudo=shutil.which("sudo")
    if not sudo:
        return _finish(r,"SKIPPED_GUARDRAIL",False,"passwordless sudo unavailable for proven KVM boundary",
                       {"system_image":package})

    accel_code,accel_out,accel_err=_run([sudo,"-n",str(emulator),"-accel-check"],timeout=20)
    accel_ok=accel_code==0 and ("KVM" in (accel_out+accel_err).upper() or "ACCEL" in (accel_out+accel_err).upper())
    if not accel_ok:
        return _finish(r,"ORACLE_FAILURE",False,"Android emulator acceleration check failed",
                       {"system_image":package,"exit_code":accel_code,
                        "stdout":accel_out[:1200],"stderr":accel_err[:1200]})

    with tempfile.TemporaryDirectory(prefix="runner-android-frontier-") as td:
        root=pathlib.Path(td)
        avd_home=root/"avd"; avd_home.mkdir()
        android_home=root/"android-home"; android_home.mkdir()
        env=os.environ.copy()
        env.update({
            "ANDROID_AVD_HOME":str(avd_home),
            "ANDROID_USER_HOME":str(android_home),
            "HOME":str(root/"home"),
        })
        pathlib.Path(env["HOME"]).mkdir()
        name="runnerfrontier"
        create_code,create_out,create_err=_run(
            [str(avdmanager),"create","avd","--force","--name",name,
             "--package",package,"--device","pixel_6"],
            timeout=30,env=env,stdin="no\n")
        if create_code!=0:
            return _finish(r,"HARNESS_FAILURE",False,"AVD creation from preinstalled system image failed",
                           {"system_image":package,"exit_code":create_code,
                            "stdout":create_out[:1000],"stderr":create_err[:1500]})

        cmd=[sudo,"-n","env",
             f"ANDROID_AVD_HOME={avd_home}",f"ANDROID_USER_HOME={android_home}",
             f"HOME={env['HOME']}",
             str(emulator),"-avd",name,"-no-window","-no-audio","-no-boot-anim",
             "-no-snapshot-load","-no-snapshot-save","-accel","on","-gpu","swiftshader_indirect",
             "-no-metrics"]
        proc=subprocess.Popen(cmd,stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True,env=env)
        serial=None; boot_value=""; adb_error=""; started=time.monotonic()
        try:
            deadline=time.monotonic()+150
            while time.monotonic()<deadline:
                code,out,err=_run([sudo,"-n",str(adb),"devices"],timeout=10,env=env)
                if code==0:
                    for line in out.splitlines():
                        if line.startswith("emulator-") and "\tdevice" in line:
                            serial=line.split("\t",1)[0]; break
                if serial:
                    break
                if proc.poll() is not None:
                    break
                time.sleep(2)
            if serial:
                while time.monotonic()<deadline:
                    code,out,err=_run([sudo,"-n",str(adb),"-s",serial,"shell","getprop","sys.boot_completed"],
                                      timeout=10,env=env)
                    if code==0 and out.strip()=="1":
                        boot_value="1"; break
                    adb_error=err
                    time.sleep(2)
            passed=serial is not None and boot_value=="1"
            elapsed=time.monotonic()-started
            if passed:
                qcode,qout,qerr=_run([sudo,"-n",str(adb),"-s",serial,"shell","getprop","ro.product.cpu.abi"],
                                     timeout=10,env=env)
            else:
                qcode,qout,qerr=None,"",""
        finally:
            if serial:
                _run([sudo,"-n",str(adb),"-s",serial,"emu","kill"],timeout=15,env=env)
            try:
                proc.terminate()
                proc.wait(timeout=10)
            except Exception:
                try: proc.kill()
                except Exception: pass
            _run([sudo,"-n",str(adb),"kill-server"],timeout=10,env=env)
        if passed:
            return _finish(r,"SUPPORTED",True,"preinstalled Android x86_64 image booted with KVM acceleration",
                           {"system_image":package,"serial":serial,"boot_completed":boot_value,
                            "guest_abi":qout.strip() if qcode==0 else None,
                            "elapsed_seconds":round(elapsed,3),
                            "accel_check":(accel_out+"\n"+accel_err).strip()[:1200]})
        return _finish(r,"ORACLE_FAILURE",False,"Android emulator did not reach boot_completed within bounded window",
                       {"system_image":package,"serial":serial,"boot_completed":boot_value or None,
                        "elapsed_seconds":round(elapsed,3),"adb_error":adb_error[:1000] or None,
                        "emulator_exit":proc.poll()})

def qualify_ios_sdk_compile(label:str)->dict[str,Any]:
    r=_base(label,"ios-simulator-sdk-compile")
    if platform.system()!="Darwin":
        return _finish(r,"SKIPPED_GUARDRAIL",False,"iOS SDK compile workload is macOS-only",{})
    xcrun=shutil.which("xcrun")
    if not xcrun:
        return _finish(r,"SKIPPED_GUARDRAIL",False,"xcrun not present",{})
    scode,sdk_path,serr=_run([xcrun,"--sdk","iphonesimulator","--show-sdk-path"],timeout=20)
    ccode,clang,cerr=_run([xcrun,"--sdk","iphonesimulator","--find","clang"],timeout=20)
    if scode!=0 or ccode!=0 or not sdk_path or not clang:
        return _finish(r,"ORACLE_FAILURE",False,"iPhoneSimulator SDK or clang lookup failed",
                       {"sdk_exit":scode,"clang_exit":ccode,"stderr":(serr+"\n"+cerr)[:1200]})
    host=platform.machine()
    arch="arm64" if host=="arm64" else "x86_64"
    target=f"{arch}-apple-ios18.0-simulator"
    with tempfile.TemporaryDirectory(prefix="runner-ios-build-") as td:
        root=pathlib.Path(td)
        src=root/"frontier.c"; obj=root/"frontier.o"
        src.write_text("int frontier_value(void){return 42;}\n",encoding="utf-8")
        started=time.monotonic()
        code,out,err=_run([clang,"-target",target,"-isysroot",sdk_path,
                           "-Wall","-Werror","-c",str(src),"-o",str(obj)],timeout=60)
        elapsed=time.monotonic()-started
        fcode,fout,ferr=_run(["/usr/bin/file",str(obj)],timeout=10) if obj.exists() else (None,"","")
    expected=("arm64" in fout) if arch=="arm64" else ("x86_64" in fout or "x86-64" in fout)
    passed=code==0 and fcode==0 and expected
    evidence={"sdk_path":sdk_path,"clang":clang,"target":target,"compile_exit":code,
              "object_file":fout[:1000] if fout else None,"elapsed_seconds":round(elapsed,3),
              "stderr":(err+"\n"+ferr).strip()[:1200] or None}
    return _finish(r,"SUPPORTED" if passed else "ORACLE_FAILURE",passed,
                   "iPhoneSimulator SDK compiled a target-architecture object" if passed
                   else "iPhoneSimulator SDK compile oracle failed",evidence)

WORKLOADS={
    "android-emulator":qualify_android_emulator,
    "ios-sdk-compile":qualify_ios_sdk_compile,
}

def main()->int:
    p=argparse.ArgumentParser()
    p.add_argument("--workload",choices=sorted(WORKLOADS),required=True)
    p.add_argument("--label",required=True)
    p.add_argument("--out",required=True)
    a=p.parse_args()
    receipt=WORKLOADS[a.workload](a.label)
    path=pathlib.Path(a.out); path.parent.mkdir(parents=True,exist_ok=True)
    path.write_text(json.dumps(receipt,indent=2,sort_keys=True)+"\n",encoding="utf-8")
    print(f"FRONTIER_WORKLOAD_RECEIPT={path}")
    print(json.dumps(receipt,indent=2,sort_keys=True))
    return 0

if __name__=="__main__":
    raise SystemExit(main())
