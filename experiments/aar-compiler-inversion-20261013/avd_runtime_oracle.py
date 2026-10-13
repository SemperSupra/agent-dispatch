#!/usr/bin/env python3
"""Public synthetic DEX runtime oracle on one disposable accelerated Android AVD.

Reuses Agent Dispatch's already-qualified Android emulator package/boot pattern.
Executes only the authored DEX emitted by pilot.py. Does not open private APKs.
"""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import platform
import shutil
import subprocess
import sys
import time

ROOT=Path(os.environ.get("RUNNER_TEMP","/tmp"))/"aar-inversion"
OUT=ROOT/"avd-runtime-receipt.json"
MODES=("d8_only","r8_rename","r8_optimize")
SAMPLES=("-3","0","1","2","7","13")
SDK=Path(os.environ.get("ANDROID_HOME") or "/usr/local/lib/android/sdk")
result={
 "schema":"aar-avd-dex-runtime/v1",
 "scope":"PUBLIC_AUTHORED_DEX_ONLY",
 "source":"pilot.py exact current branch",
 "guest":"API35-google_apis-x86_64",
 "classification":"NOT_RUN",
 "guest_execution":{},
 "warnings":[],
 "provenance":{"head":os.environ.get("GITHUB_SHA",""),"run_id":os.environ.get("GITHUB_RUN_ID","")}
}
def save():
    OUT.parent.mkdir(parents=True,exist_ok=True)
    OUT.write_text(json.dumps(result,sort_keys=True,indent=2)+"\n")
    print("AAR_ANDROID_RUNTIME="+json.dumps({
        "classification":result["classification"],
        "guest_execution":{k:{"status":v.get("status"),"count":v.get("matched_inputs",0)}
                           for k,v in result["guest_execution"].items()}},sort_keys=True))
def cmd(argv,timeout=50,env=None,stdin=None):
    return subprocess.run([str(a) for a in argv],input=stdin,stdout=subprocess.PIPE,stderr=subprocess.PIPE,
                          text=True,errors="replace",check=False,timeout=timeout,env=env)
def fail(reason,classification="ENVIRONMENT_FAILURE"):
    result["classification"]=classification
    result["reason"]=reason
    save()
    return 1
def main():
    save()
    if platform.system()!="Linux" or platform.machine()!="x86_64":
        return fail("x64_ubuntu_only","SKIPPED_GUARDRAIL")
    sudo=shutil.which("sudo")
    sdkmanager=SDK/"cmdline-tools"/"latest"/"bin"/"sdkmanager"
    avdmanager=SDK/"cmdline-tools"/"latest"/"bin"/"avdmanager"
    emulator=SDK/"emulator"/"emulator"
    adb=SDK/"platform-tools"/"adb"
    if not sudo or not all(p.is_file() for p in (sdkmanager,avdmanager,adb)):
        return fail("sdk_entry_gate_missing","SKIPPED_GUARDRAIL")
    pilot=ROOT/"receipt.json"
    if not pilot.is_file():
        return fail("missing_independently_qualified_compiler_pilot","HARNESS_FAILURE")
    prior=json.loads(pilot.read_text())
    if prior.get("overall")!="PASS_JVM_AND_DEX_STATIC_WITH_NEGATIVES":
        return fail("compiler_pilot_not_qualified","HARNESS_FAILURE")
    if set(prior.get("experiments",{}))!=set(MODES):
        return fail("compiler_treatment_set_mismatch","HARNESS_FAILURE")
    expect=prior.get("oracle",{}).get("expected_outputs",{})
    if set(expect)!=set(SAMPLES):
        return fail("missing_runtime_oracle_inputs","HARNESS_FAILURE")
    dexes={}
    for mode in MODES:
        source=ROOT/mode/"dex"/"classes.dex"
        if not source.is_file() or hashlib.sha256(source.read_bytes()).hexdigest()!=prior["experiments"][mode]["dex_sha256"]:
            return fail("exact_compiled_dex_identity_failed_"+mode,"HARNESS_FAILURE")
        dexes[mode]=source
    start=time.monotonic()
    package="system-images;android-35;google_apis;x86_64"
    try:
        install=cmd([sudo,"-n",sdkmanager,"--install","emulator",package],timeout=380,stdin="y\n"*200)
    except subprocess.TimeoutExpired:
        return fail("sdk_install_timeout")
    result["setup_elapsed_s"]=round(time.monotonic()-start,2)
    if install.returncode or not emulator.is_file() or not (SDK/"system-images"/"android-35"/"google_apis"/"x86_64").is_dir():
        return fail("sdk_install_failed_exit_"+str(install.returncode))
    scratch=ROOT/"avd_guest"
    avd_home=scratch/"avd"
    android_home=scratch/"android-home"
    home=scratch/"home"
    for p in (avd_home,android_home,home):
        p.mkdir(parents=True,exist_ok=True)
    env=os.environ.copy()
    env.update({"ANDROID_AVD_HOME":str(avd_home),"ANDROID_USER_HOME":str(android_home),"HOME":str(home)})
    serial=None
    process=None
    try:
        created=cmd([avdmanager,"create","avd","--force","--name","aarqual",
                     "--package",package,"--device","pixel_6"],timeout=40,env=env,stdin="no\n")
        if created.returncode:
            return fail("avd_creation_failed","ENVIRONMENT_FAILURE")
        acceleration=cmd([sudo,"-n",emulator,"-accel-check"],timeout=25,env=env)
        if acceleration.returncode:
            return fail("avd_acceleration_missing","ENVIRONMENT_FAILURE")
        emulator_cmd=[sudo,"-n","env",f"ANDROID_AVD_HOME={avd_home}",f"ANDROID_USER_HOME={android_home}",
                      f"HOME={home}",str(emulator),"-avd","aarqual","-no-window","-no-audio",
                      "-no-boot-anim","-no-snapshot-load","-no-snapshot-save",
                      "-accel","on","-gpu","swiftshader_indirect","-no-metrics"]
        with open(ROOT/"emulator-stdout.log","w") as o,open(ROOT/"emulator-stderr.log","w") as e:
            # Files are used only as local disposal buffers; they are NOT uploaded.
            process=subprocess.Popen(emulator_cmd,stdout=o,stderr=e,env=env)
            deadline=time.monotonic()+170
            booted=False
            while time.monotonic()<deadline and process.poll() is None:
                try:
                    devices=cmd([sudo,"-n",adb,"devices"],timeout=12,env=env)
                    for line in devices.stdout.splitlines():
                        if line.startswith("emulator-") and "\tdevice" in line:
                            serial=line.split("\t")[0]
                            break
                    if serial:
                        p=cmd([sudo,"-n",adb,"-s",serial,"shell","getprop","sys.boot_completed"],timeout=12,env=env)
                        booted=p.returncode==0 and p.stdout.strip()=="1"
                        if booted:break
                except subprocess.TimeoutExpired: pass
                time.sleep(3)
            if not booted:
                return fail("emulator_guest_did_not_boot","ENVIRONMENT_FAILURE")
            result["guest_booted"]=True
            abi=cmd([sudo,"-n",adb,"-s",serial,"shell","getprop","ro.product.cpu.abi"],timeout=20,env=env)
            if abi.returncode or "x86_64" not in abi.stdout:
                return fail("guest_abi_mismatch","ORACLE_FAILURE")
            # Execute each authentic DEX directly through ART/dalvikvm.
            for mode in MODES:
                remote=f"/data/local/tmp/aar_inversion_{mode}.dex"
                pushed=cmd([sudo,"-n",adb,"-s",serial,"push",dexes[mode],remote],timeout=35,env=env)
                if pushed.returncode:
                    return fail("dex_adb_push_failed_"+mode,"ENVIRONMENT_FAILURE")
                observed={}
                for value in SAMPLES:
                    try:
                        run=cmd([sudo,"-n",adb,"-s",serial,"shell",
                                 "dalvikvm","-cp",remote,"Probe",value],timeout=28,env=env)
                    except subprocess.TimeoutExpired:
                        return fail("dex_runtime_timeout_"+mode,"ORACLE_FAILURE")
                    if run.returncode:
                        result["guest_execution"][mode]={"status":"FAIL_GUEST_EXIT","exit_code":run.returncode,
                                                          "input":value,"matched_inputs":len(observed)}
                        return fail("dex_guest_execution_failed_"+mode,"ORACLE_FAILURE")
                    observed[value]=run.stdout.strip()
                    if observed[value]!=expect[value]:
                        result["guest_execution"][mode]={"status":"FAIL_ORACLE_MISMATCH",
                                                          "input":value,"matched_inputs":len(observed)-1}
                        return fail("dex_guest_semantics_mismatch_"+mode,"ORACLE_FAILURE")
                result["guest_execution"][mode]={"status":"PASS_GUEST_RUNTIME_ORACLE",
                                                   "matched_inputs":len(observed),
                                                   "dex_sha256":prior["experiments"][mode]["dex_sha256"]}
            result["classification"]="SUPPORTED_AND_ORACLE_PASSED"
            result["elapsed_s"]=round(time.monotonic()-start,2)
            save()
            return 0
    finally:
        if serial:
            try:cmd([sudo,"-n",adb,"-s",serial,"emu","kill"],timeout=18,env=env)
            except Exception:pass
        if process:
            try:process.terminate();process.wait(timeout=9)
            except Exception:
                try:process.kill()
                except Exception:pass
        try:cmd([sudo,"-n",adb,"kill-server"],timeout=15,env=env)
        except Exception:pass
        # Explicit experiment-owned directory only, never a user's AVD.
        try:cmd([sudo,"-n","rm","-rf","--",str(scratch)],timeout=25,env=env)
        except Exception:pass

try:
    sys.exit(main())
except Exception as ex:
    sys.exit(fail("harness_exception_"+type(ex).__name__,"HARNESS_FAILURE"))
