#!/usr/bin/env python3
"""R50: genuine Xcode project -> iPhone Simulator app install/launch oracle.

This is NOT an iOS physical-device test, background-workload test or MDM
test. No developer account, production signing identity or real phone access.
"""
from __future__ import annotations

import argparse
import json
import os
import pathlib
import platform
import plistlib
import shutil
import sys
import tempfile
import time
import uuid

sys.path.insert(0,str(pathlib.Path(__file__).resolve().parent))
import github_runner_frontier as frontier

BUNDLE="com.sempersupra.r50.ios"
PROJECT=pathlib.Path(__file__).resolve().parents[1]/"tools"/"r50-ios-app"/"R50Companion.xcodeproj"

def launched_from_sandbox(status, launch_exit, installed, container_observed):
    return (launch_exit==0 and installed and container_observed and
            status=="R50_IOS_APP_LAUNCHED")

def rec(classification,reason,evidence):
    return {
      "schema":"r50-ios-xcode-app-lifecycle/v1",
      "substrate":"MACOS26_INTEL_XCODE_PROJECT_IPHONE_SIMULATOR_NOT_PHYSICAL",
      "classification":classification,
      "reason":reason,
      "evidence":evidence,
      "provenance":{
        "workflow_sha":os.environ.get("GITHUB_SHA",""),
        "run_id":os.environ.get("GITHUB_RUN_ID",""),
        "image_version":os.environ.get("ImageVersion",""),
      },
      "physical_iphone_secure_enclave_cellular_battery_thermal":"NOT_TESTED",
      "ios_background_tasks_mdm_appstore":"NOT_TESTED",
    }

def observe_app_prefs(data_container):
    candidate=pathlib.Path(data_container)/"Library"/"Preferences"/(BUNDLE+".plist")
    if not candidate.is_file():
        return None
    try:
        with candidate.open("rb") as f: values=plistlib.load(f)
        if isinstance(values,dict):
            return values.get("r50.status")
    except (OSError,ValueError,plistlib.InvalidFileException):
        return None
    return None

def exercise():
    evidence={"xcode_project_build":"NOT_PROVEN","simulator_boot":"NOT_PROVEN",
              "simulator_app_install":"NOT_PROVEN","simulator_app_launch":"NOT_PROVEN",
              "independent_app_sandbox_oracle":"NOT_PROVEN"}
    if (os.environ.get("GITHUB_ACTIONS")!="true" or platform.system()!="Darwin" or
        platform.machine()!="x86_64"):
        return rec("SKIPPED_GUARDRAIL","ONLY_PREVIOUSLY_PROVEN_INTEL_MACOS26_SIMULATOR",evidence)
    xcrun=shutil.which("xcrun")
    xcodebuild=shutil.which("xcodebuild")
    codesign=shutil.which("codesign")
    if not xcrun or not xcodebuild or not codesign or not PROJECT.is_dir():
        return rec("SKIPPED_GUARDRAIL","XCODE_PROJECT_OR_TOOLCHAIN_ABSENT",evidence)
    runtime,device_type,probe=frontier._latest_ios_and_iphone(xcrun)
    if not runtime or not device_type:
        evidence["simulator_runtime_probe"]="NO_ADMITTED_IPHONE_PAIR"
        return rec("SKIPPED_GUARDRAIL","IPHONE_SIMULATOR_RUNTIME_NOT_ADMITTED",evidence)
    evidence["simulator_runtime"]=runtime.get("identifier","UNKNOWN")
    evidence["simulator_device_type"]=device_type.get("identifier","UNKNOWN")
    with tempfile.TemporaryDirectory(prefix="r50-ios-xcode-") as temp:
        root=pathlib.Path(temp);derived=root/"DerivedData"
        build_cmd=[
            xcodebuild,"-project",str(PROJECT),"-scheme","R50Companion",
            "-configuration","Debug","-sdk","iphonesimulator",
            "-destination","generic/platform=iOS Simulator",
            "-derivedDataPath",str(derived),
            "CODE_SIGNING_ALLOWED=NO","ARCHS=x86_64","ONLY_ACTIVE_ARCH=YES",
            "build"
        ]
        started=time.monotonic()
        code,_,err=frontier._run(build_cmd,timeout=180)
        evidence["xcode_build_seconds"]=round(time.monotonic()-started,2)
        evidence["xcode_project_build"]="PASS" if code==0 else "NOT_PROVEN"
        if code!=0:
            evidence["xcode_error_tail"]=err[-850:]
            return rec("HARNESS_FAILURE","REAL_XCODE_PROJECT_BUILD_FAILED",evidence)
        app=derived/"Build"/"Products"/"Debug-iphonesimulator"/"R50Companion.app"
        if not app.is_dir() or not (app/"R50Companion").is_file() or not (app/"Info.plist").is_file():
            return rec("HARNESS_FAILURE","XCODE_BUILT_APP_BUNDLE_MISSING",evidence)
        try:
            with (app/"Info.plist").open("rb") as f: pl=plistlib.load(f)
        except (OSError,ValueError,plistlib.InvalidFileException):
            return rec("HARNESS_FAILURE","XCODE_GENERATED_PLIST_NOT_VALID",evidence)
        if pl.get("CFBundleIdentifier")!=BUNDLE:
            return rec("HARNESS_FAILURE","XCODE_GENERATED_APP_BUNDLE_ID_MISMATCH",evidence)
        # Simulator-only ad-hoc signing, NO Apple Developer identity or
        # provisioned device certificate. Different from previous manually
        # assembled bundle that failed simctl install (#223).
        sign,_,_=frontier._run([codesign,"--force","--sign","-","--timestamp=none",str(app)],timeout=30)
        verify,_,_=frontier._run([codesign,"--verify","--strict","--deep",str(app)],timeout=30)
        if sign!=0 or verify!=0:
            return rec("HARNESS_FAILURE","EPHEMERAL_SIMULATOR_APP_SIGNATURE_FAILED",evidence)
        evidence["simulator_signature"]="ADHOC_VERIFIED_NONPRODUCTION"
        name="R50Xcode-"+uuid.uuid4().hex[:8]
        create,udid,_=frontier._run([xcrun,"simctl","create",name,
            device_type["identifier"],runtime["identifier"]],timeout=40)
        udid=udid.strip()
        if create!=0 or not udid:
            return rec("ENVIRONMENT_FAILURE","DISPOSABLE_IPHONE_SIMULATOR_CREATION_FAILED",evidence)
        installed=False
        try:
            boot,_,_=frontier._run([xcrun,"simctl","boot",udid],timeout=40)
            if boot!=0:
                return rec("ENVIRONMENT_FAILURE","DISPOSABLE_IPHONE_SIMULATOR_BOOT_COMMAND_FAILED",evidence)
            deadline=time.monotonic()+105
            booted=False
            while time.monotonic()<deadline:
                state,_=frontier._device_state(xcrun,udid)
                if state=="Booted":booted=True;break
                time.sleep(2)
            evidence["simulator_boot"]="BOOTED" if booted else "NOT_PROVEN"
            if not booted:return rec("ORACLE_FAILURE","IPHONE_SIMULATOR_BOOT_ORACLE_FAILED",evidence)
            # Booted means CoreSimulator recognized the guest, not that its
            # app installation services are ready. Require the separately
            # documented bounded bootstatus before attempting app install.
            ready,_,bootstatus_err=frontier._run(
                [xcrun,"simctl","bootstatus",udid,"-b"],timeout=80)
            evidence["simulator_boot_services_ready"]="PASS" if ready==0 else "NOT_PROVEN"
            if ready!=0:
                evidence["bootstatus_error_tail"]=bootstatus_err[-450:]
                return rec("ENVIRONMENT_FAILURE","SIMULATOR_BOOT_SERVICES_NOT_READY",evidence)
            c,_,_=frontier._run([xcrun,"simctl","spawn",udid,"/usr/bin/true"],timeout=20)
            if c!=0:return rec("ORACLE_FAILURE","IPHONE_SIMULATOR_GUEST_SPAWN_FAILED",evidence)
            install_started=time.monotonic()
            c,_,install_err=frontier._run([xcrun,"simctl","install",udid,str(app)],timeout=30)
            evidence["simctl_install_exit"]=c
            evidence["simctl_install_seconds"]=round(time.monotonic()-install_started,2)
            if c!=0:
                evidence["simctl_install_error_tail"]=install_err[-900:]
                return rec("ORACLE_FAILURE","XCODE_APP_SIMCTL_INSTALL_FAILED",evidence)
            installed=True
            evidence["simulator_app_install"]="PASS"
            c,_,_=frontier._run([xcrun,"simctl","launch",udid,BUNDLE],timeout=30)
            evidence["simulator_app_launch"]="EXIT_ZERO" if c==0 else "NOT_PROVEN"
            if c!=0:return rec("ORACLE_FAILURE","XCODE_APP_SIMCTL_LAUNCH_FAILED",evidence)
            pcode,data_path,_=frontier._run([xcrun,"simctl","get_app_container",udid,BUNDLE,"data"],timeout=30)
            container_observed=pcode==0 and bool(data_path.strip())
            state=None
            if container_observed:
                for _ in range(12):
                    state=observe_app_prefs(data_path.strip())
                    if state=="R50_IOS_APP_LAUNCHED":break
                    time.sleep(1)
            evidence["independent_app_sandbox_oracle"]="PERSISTED" if state=="R50_IOS_APP_LAUNCHED" else "NOT_PROVEN"
            if not launched_from_sandbox(state,c,installed,container_observed):
                return rec("ORACLE_FAILURE","XCODE_APP_PRIVATE_LAUNCH_STATE_UNPROVEN",evidence)
            t,_,_=frontier._run([xcrun,"simctl","terminate",udid,BUNDLE],timeout=20)
            evidence["simulator_app_terminate"]="PASS" if t==0 else "NOT_PROVEN"
            if t!=0:return rec("ORACLE_FAILURE","XCODE_APP_TERMINATE_FAILED",evidence)
            return rec("SUPPORTED","XCODE_APP_INSTALL_LAUNCH_PRIVATE_SANDBOX_AND_TERMINATE_PASS",evidence)
        finally:
            if installed:
                frontier._run([xcrun,"simctl","uninstall",udid,BUNDLE],timeout=25)
            frontier._run([xcrun,"simctl","shutdown",udid],timeout=25)
            frontier._run([xcrun,"simctl","delete",udid],timeout=25)

def main():
    p=argparse.ArgumentParser();p.add_argument("--out",required=True);a=p.parse_args()
    report=exercise()
    path=pathlib.Path(a.out);path.parent.mkdir(parents=True,exist_ok=True)
    path.write_text(json.dumps(report,sort_keys=True,indent=2)+"\n",encoding="utf-8")
    print("R50_IOS_XCODE_APP_VERDICT="+report["classification"])
    print("R50_IOS_XCODE_APP_REASON="+report["reason"])
    print("R50_REAL_IPHONE_APP_BACKGROUND_AND_MDM=NOT_TESTED")
    return 0 if report["classification"]=="SUPPORTED" else 1
if __name__=="__main__":raise SystemExit(main())
