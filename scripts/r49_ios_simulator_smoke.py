#!/usr/bin/env python3
"""R49: fresh CoreSimulator boot and framebuffer primitive on public macOS.

No iOS app install/launch is asserted: the earlier manual synthetic bundle
timed out at simctl install. No access to physical iPhone/iPad/MDM/Apple ID.
"""
from __future__ import annotations
import argparse
import hashlib
import json
import os
import pathlib
import platform
import shutil
import struct
import sys
import tempfile
import time
import uuid

sys.path.insert(0,str(pathlib.Path(__file__).resolve().parent))
import github_runner_frontier as frontier

def png_dimensions(data):
    if len(data)<24 or data[:8]!=b"\x89PNG\r\n\x1a\n" or data[12:16]!=b"IHDR":
        return None
    width,height=struct.unpack(">II",data[16:24])
    if not (100<=width<=6000 and 100<=height<=6000):
        return None
    return (width,height)

def receipt(kind,reason,evidence):
    return {
        "schema":"r49-ios-coresimulator-primitives/v1",
        "parent":"PUBLIC_GHA_MACOS_CORESIMULATOR_NOT_PHYSICAL_IOS",
        "classification":kind,
        "reason":reason,
        "provenance":{
            "workflow_sha":os.environ.get("GITHUB_SHA",""),
            "run_id":os.environ.get("GITHUB_RUN_ID",""),
            "image_version":os.environ.get("ImageVersion",""),
        },
        "evidence":evidence,
        "ios_app_install_launch_background_and_mdm":"NOT_TESTED",
        "physical_iphone_thermal_radio_secure_enclave":"NOT_TESTED",
    }

def assess(booted,getenv_ok,spawn_ok,png_shape):
    if not booted:return False,"IOS_SIMULATOR_NOT_BOOTED"
    if not getenv_ok or not spawn_ok:return False,"IOS_SIMULATOR_GUEST_PRIMITIVES_NOT_OBSERVED"
    if png_shape is None:return False,"IOS_SIMULATOR_FRAMEBUFFER_ORACLE_FAILED"
    return True,"CORESIMULATOR_BOOT_SPAWN_SCREENSHOT_PASS"

def run_qualified(label):
    ev={"runner":label,"ios_sdk":"NOT_TESTED","core_simulator_boot":"NOT_TESTED",
        "guest_spawn":"NOT_TESTED","framebuffer_capture":"NOT_TESTED"}
    supported={"macos-26-intel":"x86_64","macos-26":"arm64"}
    if os.environ.get("GITHUB_ACTIONS")!="true" or platform.system()!="Darwin" or platform.machine()!=supported.get(label):
        return receipt("SKIPPED_GUARDRAIL","NOT_ADMITTED_SIMULATOR_HOST_OR_ARCH",ev)
    xcrun=shutil.which("xcrun")
    if not xcrun:return receipt("SKIPPED_GUARDRAIL","XCODE_COMMAND_LINE_NOT_PRESENT",ev)
    runtime,devtype,probe=frontier._latest_ios_and_iphone(xcrun)
    ev["runtime_query_exit"]=probe.get("runtime_exit")
    ev["device_type_query_exit"]=probe.get("device_type_exit")
    ev["runtime_selection"]="AVAILABLE" if runtime else "MISSING"
    ev["iphone_type_selection"]="AVAILABLE" if devtype else "MISSING"
    if not runtime or not devtype:
        return receipt("SKIPPED_GUARDRAIL","IOS_RUNTIME_OR_IPHONE_TYPE_UNAVAILABLE",ev)
    rc,sdk,_=frontier._run([xcrun,"--sdk","iphonesimulator","--show-sdk-path"],timeout=20)
    if rc!=0 or not sdk:
        return receipt("ENVIRONMENT_FAILURE","IOS_SIMULATOR_SDK_UNAVAILABLE",ev)
    ev["ios_sdk"]="OBSERVED_INSTALLED"
    ev["runtime"]=runtime.get("identifier","UNKNOWN")
    ev["device_type"]=devtype.get("identifier","UNKNOWN")
    with tempfile.TemporaryDirectory(prefix="r49-ios-") as td:
        root=pathlib.Path(td)
        name="R49Companion-"+uuid.uuid4().hex[:8]
        code,simid,_=frontier._run([xcrun,"simctl","create",name,devtype["identifier"],runtime["identifier"]],timeout=30)
        simid=simid.strip()
        if code!=0 or not simid:
            return receipt("ENVIRONMENT_FAILURE","CORESIMULATOR_DISPOSABLE_DEVICE_CREATION_FAILED",ev)
        booted=False;getenv_ok=False;spawn_ok=False;png_shape=None
        try:
            code,_,_ = frontier._run([xcrun,"simctl","boot",simid],timeout=45)
            if code!=0:return receipt("ORACLE_FAILURE","CORESIMULATOR_BOOT_COMMAND_FAILED",ev)
            deadline=time.monotonic()+100
            while time.monotonic()<deadline:
                state,_=frontier._device_state(xcrun,simid)
                if state=="Booted":booted=True;break
                time.sleep(2)
            ev["core_simulator_boot"]="BOOTED" if booted else "NOT_PROVEN"
            if booted:
                rc,home,_=frontier._run([xcrun,"simctl","getenv",simid,"HOME"],timeout=20)
                getenv_ok=rc==0 and bool(home.strip())
                rc,_,_=frontier._run([xcrun,"simctl","spawn",simid,"/usr/bin/true"],timeout=20)
                spawn_ok=rc==0
                ev["guest_spawn"]="PASS" if spawn_ok else "NOT_PROVEN"
                shot=root/"frame.png"
                rc,_,_=frontier._run([xcrun,"simctl","io",simid,"screenshot","--type=png",str(shot)],timeout=35)
                if rc==0 and shot.exists():
                    dat=shot.read_bytes()
                    png_shape=png_dimensions(dat)
                    if png_shape:
                        ev["screen_width_px"],ev["screen_height_px"]=png_shape
                        ev["synthetic_screen_sha256"]=hashlib.sha256(dat).hexdigest()
                ev["framebuffer_capture"]="PNG_OBSERVED" if png_shape else "NOT_PROVEN"
            passed,why=assess(booted,getenv_ok,spawn_ok,png_shape)
            return receipt("SUPPORTED" if passed else "ORACLE_FAILURE",why,ev)
        finally:
            frontier._run([xcrun,"simctl","shutdown",simid],timeout=25)
            frontier._run([xcrun,"simctl","delete",simid],timeout=25)

def main():
    parser=argparse.ArgumentParser()
    parser.add_argument("--label",required=True)
    parser.add_argument("--out",required=True)
    opts=parser.parse_args()
    r=run_qualified(opts.label)
    p=pathlib.Path(opts.out);p.parent.mkdir(parents=True,exist_ok=True)
    p.write_text(json.dumps(r,sort_keys=True,indent=2)+"\n",encoding="utf-8")
    print("R49_IOS_VERDICT="+r["classification"])
    print("R49_IOS_REASON="+r["reason"])
    print("R49_IOS_REAL_IPHONE_AND_APP_LIFECYCLE=NOT_TESTED")
    return 0 if r["classification"]=="SUPPORTED" else 1

if __name__=="__main__":raise SystemExit(main())
