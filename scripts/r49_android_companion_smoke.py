#!/usr/bin/env python3
"""R49: real API35 KVM AVD smoke. Public synthetic data only; not a physical phone.

This is an extension of the accepted github_runner_android_install.py pattern:
bounded download, root-only KVM on GitHub x64, isolated temporary AVD, cleanup.
"""
from __future__ import annotations
import argparse
import json
import os
import pathlib
import platform
import shutil
import subprocess
import tempfile
import time

PKGS = ["emulator", "system-images;android-35;google_apis;x86_64"]

def run(argv, timeout=30, env=None, stdin=None):
    try:
        cp = subprocess.run(argv, input=stdin, check=False, text=True,
                            capture_output=True, timeout=timeout, env=env)
        return cp.returncode, cp.stdout.strip(), cp.stderr.strip()
    except (OSError, subprocess.SubprocessError) as exc:
        return None, "", type(exc).__name__

def safe_result(evidence, classification, reason):
    return {
        "schema": "r49-mobile-android-emulator/v1",
        "parent": "PUBLIC_GHA_ANDROID_API35_X64_NOT_PHYSICAL_DEVICE",
        "provenance": {
            "workflow_sha": os.environ.get("GITHUB_SHA", ""),
            "run_id": os.environ.get("GITHUB_RUN_ID", ""),
            "image_version": os.environ.get("ImageVersion", ""),
        },
        "classification": classification,
        "reason": reason,
        "evidence": evidence,
        "physical_phone_security_thermal_radio_background": "NOT_TESTED",
        "android_app_background_or_device_owner": "NOT_TESTED",
    }

def decide(abi, api, settings_started, settings_foreground, battery_level):
    if abi != "x86_64" or api != "35":
        return False, "ANDROID_API_OR_ABI_MISMATCH"
    if not settings_started or not settings_foreground:
        return False, "SETTINGS_ACTIVITY_NOT_FOREGROUND"
    if battery_level != 73:
        return False, "EMULATED_BATTERY_ORACLE_FAILED"
    return True, "BOUNDED_ANDROID_EMULATOR_SETTINGS_AND_BATTERY_PASS"

def smoke(label):
    ev = {"runner": label, "expected_api": 35, "expected_abi": "x86_64",
          "emulator_acceleration": "NOT_TESTED",
          "settings_activity": "NOT_TESTED", "battery_simulation": "NOT_TESTED"}
    if os.environ.get("GITHUB_ACTIONS") != "true" or label != "ubuntu-24.04" or platform.machine() != "x86_64":
        return safe_result(ev, "SKIPPED_GUARDRAIL", "UNQUALIFIED_RUNNER_OR_CONTEXT")
    sdk = pathlib.Path(os.environ.get("ANDROID_HOME", "/usr/local/lib/android/sdk"))
    sdkmanager = sdk / "cmdline-tools/latest/bin/sdkmanager"
    avdmanager = sdk / "cmdline-tools/latest/bin/avdmanager"
    adb = sdk / "platform-tools/adb"
    emulator = sdk / "emulator/emulator"
    if not all(x.exists() for x in (sdkmanager,avdmanager,adb)) or not shutil.which("sudo"):
        return safe_result(ev, "SKIPPED_GUARDRAIL", "ANDROID_SDK_MANAGEMENT_ENTRY_MISSING")
    if shutil.disk_usage(sdk).free < 7 * (1024**3):
        return safe_result(ev, "SKIPPED_GUARDRAIL", "INSUFFICIENT_EPHEMERAL_DISK_FOR_API35")
    started = time.monotonic()
    rc, _out, err = run(["sudo","-n",str(sdkmanager),"--install",*PKGS],timeout=320,stdin="y\n"*200)
    ev["sdk_install_seconds"] = round(time.monotonic()-started,2)
    ev["package_set"] = PKGS
    if rc != 0 or not emulator.exists():
        return safe_result(ev, "ENVIRONMENT_FAILURE", "EMULATOR_PACKAGE_INSTALL_FAILED:" + (err[-120:] if err else str(rc)))
    accel,accel_out,accel_err = run(["sudo","-n",str(emulator),"-accel-check"],timeout=20)
    ev["emulator_acceleration"] = "KVM_CHECK_PASS" if accel==0 and "KVM" in (accel_out+accel_err).upper() else "NOT_PROVEN"
    if ev["emulator_acceleration"]!="KVM_CHECK_PASS":
        return safe_result(ev, "ORACLE_FAILURE", "KVM_ACCELERATION_GATE")
    with tempfile.TemporaryDirectory(prefix="r49-android-",ignore_cleanup_errors=True) as tmp:
        root=pathlib.Path(tmp)
        avdhome=root/"avd";userhome=root/"android-home";home=root/"home"
        for d in (avdhome,userhome,home): d.mkdir()
        env=os.environ.copy()
        env.update({"ANDROID_AVD_HOME":str(avdhome),"ANDROID_USER_HOME":str(userhome),"HOME":str(home)})
        rc,_,_ = run([str(avdmanager),"create","avd","--force","--name","r49mobile",
                      "--package",PKGS[1],"--device","pixel_6"],timeout=40,env=env,stdin="no\n")
        if rc!=0:
            return safe_result(ev,"HARNESS_FAILURE","DISPOSABLE_AVD_CREATION_FAILED")
        cmd=["sudo","-n","env","ANDROID_AVD_HOME="+str(avdhome),
             "ANDROID_USER_HOME="+str(userhome),"HOME="+str(home),
             str(emulator),"-avd","r49mobile","-no-window","-no-audio",
             "-no-boot-anim","-no-snapshot-load","-no-snapshot-save",
             "-accel","on","-gpu","swiftshader_indirect","-no-metrics"]
        proc=subprocess.Popen(cmd,stdin=subprocess.DEVNULL,stdout=subprocess.DEVNULL,
                              stderr=subprocess.DEVNULL,env=env)
        serial=None
        def adb_run(*cmd,timeout=20):
            if not serial:return None,"",""
            return run(["sudo","-n",str(adb),"-s",serial,*cmd],timeout=timeout,env=env)
        try:
            deadline=time.monotonic()+150
            boot_started=time.monotonic()
            while time.monotonic()<deadline:
                rc,out,_=run(["sudo","-n",str(adb),"devices"],timeout=12,env=env)
                if rc==0:
                    for line in out.splitlines():
                        if line.startswith("emulator-") and "\tdevice" in line:
                            serial=line.split("\t",1)[0];break
                if serial or proc.poll() is not None:break
                time.sleep(2)
            if not serial:
                return safe_result(ev,"ENVIRONMENT_FAILURE","AVD_ADB_TRANSPORT_NOT_READY")
            while time.monotonic()<deadline:
                rc,out,_=adb_run("shell","getprop","sys.boot_completed")
                if rc==0 and out.strip()=="1":break
                time.sleep(2)
            else:
                return safe_result(ev,"ORACLE_FAILURE","ANDROID_BOOT_TIMEOUT")
            ev["boot_seconds"]=round(time.monotonic()-boot_started,2)
            rc,abi,_=adb_run("shell","getprop","ro.product.cpu.abi")
            rc2,api,_=adb_run("shell","getprop","ro.build.version.sdk")
            if rc!=0 or rc2!=0:
                return safe_result(ev,"ORACLE_FAILURE","ANDROID_PROPERTY_OBSERVATION_FAILED")
            ev["observed_api"]=api.strip()
            ev["observed_abi"]=abi.strip()
            # Actor-visible app intent is distinct from verifier-only ADB
            # activity/window state. Do not interpret an exit-zero start as
            # proof of an actually resumed foreground Settings screen.
            launch,launch_out,_=adb_run("shell","am","start","-a","android.settings.SETTINGS",timeout=20)
            ev["settings_start_exit"]=launch
            foreground=False
            for _ in range(10):
                code,out,_=adb_run("shell","dumpsys","window","windows",timeout=15)
                if code==0:
                    focus=[x for x in out.splitlines() if
                           "mCurrentFocus" in x or "mFocusedApp" in x]
                    if any("com.android.settings" in x for x in focus):
                        foreground=True
                        ev["settings_focus_oracle"]="DUMPSYS_WINDOW_FOCUSED_APP"
                        break
                code,out,_=adb_run("shell","dumpsys","activity","activities",timeout=15)
                if code==0:
                    focus=[x for x in out.splitlines() if
                           "mResumedActivity" in x or "topResumedActivity" in x or
                           ("ResumedActivity:" in x and "com.android.settings" in x)]
                    if any("com.android.settings" in x for x in focus):
                        foreground=True
                        ev["settings_focus_oracle"]="DUMPSYS_ACTIVITY_RESUMED"
                        break
                time.sleep(2)
            ev["settings_activity"]="FOREGROUND" if foreground else "NOT_OBSERVED"
            ev["battery_simulation"]="NOT_PROVEN"
            # Emulator power console is an emulator test-control, not an
            # Android-app capability. Independently query battery service.
            battery_source="NONE"
            bcode,_,_=adb_run("emu","power","capacity","73",timeout=15)
            ev["emulator_power_control_exit"]=bcode
            level=None
            def observed_battery():
                code,out,_=adb_run("shell","dumpsys","battery")
                if code!=0:return None
                for line in out.splitlines():
                    if line.strip().startswith("level:"):
                        try:return int(line.split(":",1)[1].strip())
                        except ValueError:return None
                return None
            if bcode==0:
                for _ in range(5):
                    level=observed_battery()
                    if level==73:
                        battery_source="EMULATOR_CONSOLE_AND_DUMPSYS"
                        break
                    time.sleep(1)
            if level!=73:
                # Fallback is test-harness-only shell control of the virtual
                # battery service, then a distinct read-only dumpsys oracle.
                bcode,_,_=adb_run("shell","dumpsys","battery","set","level","73",timeout=15)
                ev["emulator_battery_service_control_exit"]=bcode
                if bcode==0:
                    for _ in range(5):
                        level=observed_battery()
                        if level==73:
                            battery_source="SYNTHETIC_BATTERY_SERVICE_AND_DUMPSYS"
                            break
                        time.sleep(1)
            ev["battery_simulation"]="OBSERVED_LEVEL_73" if level==73 else "NOT_PROVEN"
            ev["battery_oracle_source"]=battery_source
            passed,reason=decide(abi.strip(),api.strip(),launch==0,foreground,level)
            return safe_result(ev,"SUPPORTED" if passed else "ORACLE_FAILURE",reason)
        finally:
            if serial:
                adb_run("shell","dumpsys","battery","reset",timeout=5)
                adb_run("emu","power","capacity","100",timeout=5)
                adb_run("emu","kill",timeout=15)
            try:proc.terminate();proc.wait(timeout=8)
            except Exception:
                try:proc.kill()
                except Exception:pass
            run(["sudo","-n",str(adb),"kill-server"],timeout=10,env=env)
            # Only experiment-owned paths may be removed as root.
            run(["sudo","-n","rm","-rf","--",str(avdhome),str(userhome),str(home)],timeout=20,env=env)

def main():
    p=argparse.ArgumentParser()
    p.add_argument("--label",required=True)
    p.add_argument("--out",required=True)
    a=p.parse_args()
    receipt=smoke(a.label)
    dest=pathlib.Path(a.out)
    dest.parent.mkdir(parents=True,exist_ok=True)
    dest.write_text(json.dumps(receipt,sort_keys=True,indent=2)+"\n",encoding="utf-8")
    print("R49_ANDROID_VERDICT="+receipt["classification"])
    print("R49_ANDROID_REASON="+receipt["reason"])
    print("R49_PHYSICAL_ANDROID_APP_AGENT=NOT_TESTED")
    return 0 if receipt["classification"]=="SUPPORTED" else 1
if __name__=="__main__":raise SystemExit(main())
