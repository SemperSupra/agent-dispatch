#!/usr/bin/env python3
"""R50: Build/install/launch/observe/terminate/uninstall original Android app.

Reuse R49 accepted emulator session. App and ephemeral debug signing key
exist only in disposable CI temp space. Never enroll a real device.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import tempfile
import time
import sys

# Invoked as python scripts/... and imported as scripts.... in offline tests:
# use the repository root for both, not the interpreter's scripts/ cwd.
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
from scripts.r49_android_companion_smoke import run, smoke

PACKAGE="com.sempersupra.r50"
APP_CLASS=PACKAGE+".CompanionActivity"
SOURCE=Path(__file__).resolve().parents[1]/"tools"/"r50-android-app"

def package_oracle(contents: str, resumed: bool, installed: bool, signed: bool) -> bool:
    return bool(signed and installed and resumed and
                "R50_LAUNCHED" in contents and "android_api" in contents)

def failed(evidence, reason, kind="ORACLE_FAILURE"):
    return {"classification":kind,"reason":reason,"evidence":evidence}

def build_apk(sdk: Path, workspace: Path):
    ev={"r50_build_tools":"NOT_PROVEN","r50_signing":"NOT_PROVEN"}
    tools=sdk/"build-tools"/"35.0.1"
    jar=sdk/"platforms"/"android-35"/"android.jar"
    for p in [tools/"aapt2",tools/"d8",tools/"zipalign",tools/"apksigner",jar,
              SOURCE/"AndroidManifest.xml",SOURCE/"src"/"com"/"sempersupra"/"r50"/"CompanionActivity.java"]:
        if not p.is_file():
            return None,failed(ev,"ANDROID_APP_BUILD_DEPENDENCY_ABSENT","SKIPPED_GUARDRAIL")
    classes=workspace/"classes";classes.mkdir()
    dex=workspace/"dex";dex.mkdir()
    src=SOURCE/"src"/"com"/"sempersupra"/"r50"/"CompanionActivity.java"
    compiled=classes/"com"/"sempersupra"/"r50"/"CompanionActivity.class"
    steps=[
      ("JAVAC",["javac","-source","8","-target","8","-cp",str(jar),"-d",str(classes),str(src)],65),
      ("D8",[str(tools/"d8"),"--min-api","28","--lib",str(jar),
             "--output",str(dex),str(compiled)],65),
      ("AAPT2",[str(tools/"aapt2"),"link","-o",str(workspace/"unsigned.apk"),
               "-I",str(jar),"--manifest",str(SOURCE/"AndroidManifest.xml")],30),
      ("ZIP",["zip","-q","-j",str(workspace/"unsigned.apk"),str(dex/"classes.dex")],20),
      ("ZIPALIGN",[str(tools/"zipalign"),"-f","-p","4",
                   str(workspace/"unsigned.apk"),str(workspace/"aligned.apk")],20),
    ]
    for stage,argv,timeout in steps:
        rc,_,_=run(argv,timeout=timeout)
        if rc!=0:
            ev["r50_failed_build_stage"]=stage
            return None,failed(ev,"ANDROID_APP_BUILD_STAGE_"+stage+"_FAILED","HARNESS_FAILURE")
    ev["r50_build_tools"]="JAVAC_D8_AAPT2_ZIPALIGN_COMPLETED"
    key=workspace/"debug-only.jks"
    passwd="r50-disposable-only"
    rc,_,_=run(["keytool","-genkeypair","-alias","r50test","-keystore",str(key),
                "-storepass",passwd,"-keypass",passwd,"-keyalg","RSA",
                "-keysize","2048","-validity","1","-dname","CN=R50 CI Disposable, O=R50 Lab",
                "-noprompt"],timeout=30)
    if rc!=0:return None,failed(ev,"EPHEMERAL_SIGNER_CREATION_FAILED","HARNESS_FAILURE")
    dest=workspace/"signed-test.apk"
    rc,_,_=run([str(tools/"apksigner"),"sign","--ks",str(key),
                "--ks-pass","pass:"+passwd,"--key-pass","pass:"+passwd,
                "--out",str(dest),str(workspace/"aligned.apk")],timeout=35)
    if rc!=0:return None,failed(ev,"EPHEMERAL_APK_SIGNING_FAILED","HARNESS_FAILURE")
    rc,_,_=run([str(tools/"apksigner"),"verify","--verbose",str(dest)],timeout=20)
    if rc!=0:return None,failed(ev,"ANDROID_APK_SIGNATURE_VERIFY_FAILED","ORACLE_FAILURE")
    ev["r50_signing"]="DISPOSABLE_TEST_CERT_APKSIGNER_VERIFIED"
    ev["r50_apk_sha256"]=hashlib.sha256(dest.read_bytes()).hexdigest()
    return dest,{"evidence":ev}

def live_probe(adb_run,sdk,env):
    del env
    with tempfile.TemporaryDirectory(prefix="r50-android-app-") as temp:
        apk,build=build_apk(sdk,Path(temp))
        ev=build["evidence"]
        if apk is None:return build
        installed=False
        try:
            rc,_,_=adb_run("install","-r",str(apk),timeout=50)
            ev["r50_install_exit"]=rc
            if rc!=0:return failed(ev,"ANDROID_APK_INSTALL_FAILED")
            installed=True
            rc,_,_=adb_run("shell","pm","path",PACKAGE,timeout=12)
            if rc!=0:return failed(ev,"ANDROID_PACKAGE_PATH_QUERY_FAILED")
            rc,_,_=adb_run("shell","am","start","-W","-n",PACKAGE+"/"+APP_CLASS,timeout=35)
            ev["r50_activity_start_exit"]=rc
            if rc!=0:return failed(ev,"ANDROID_ACTIVITY_START_FAILED")
            resumed=False
            for _ in range(9):
                rc,out,_=adb_run("shell","dumpsys","activity","activities",timeout=18)
                if rc==0 and any(PACKAGE in line for line in out.splitlines() if
                    "mResumedActivity" in line or "topResumedActivity" in line or
                    "ResumedActivity:" in line):
                    resumed=True;break
                time.sleep(2)
            ev["r50_activity_resumed"]="PASS" if resumed else "NOT_PROVEN"
            prefs=""
            for _ in range(6):
                rc,prefs,_=adb_run("shell","run-as",PACKAGE,"cat",
                                   "shared_prefs/r50_oracle.xml",timeout=15)
                if rc==0 and "R50_LAUNCHED" in prefs:break
                time.sleep(1)
            ev["r50_private_sandbox_oracle"]="PERSISTED" if "R50_LAUNCHED" in prefs else "NOT_PROVEN"
            if not package_oracle(prefs,resumed,installed,
                                  ev["r50_signing"]=="DISPOSABLE_TEST_CERT_APKSIGNER_VERIFIED"):
                return failed(ev,"ANDROID_APP_LAUNCH_SANDBOX_ORACLE_FAILED")
            rc,_,_=adb_run("shell","am","force-stop",PACKAGE,timeout=15)
            ev["r50_force_stop_exit"]=rc
            if rc!=0:return failed(ev,"ANDROID_APP_FORCE_STOP_FAILED")
            return {"classification":"SUPPORTED","reason":"ANDROID_SIGNED_DEBUG_APP_INSTALL_LAUNCH_APP_SANDBOX_ORACLE_PASS","evidence":ev}
        finally:
            if installed:
                code,_,_=adb_run("uninstall",PACKAGE,timeout=25)
                ev["r50_uninstall_exit"]=code

def main():
    p=argparse.ArgumentParser()
    p.add_argument("--out",required=True)
    args=p.parse_args()
    result=smoke("ubuntu-24.04",live_probe=live_probe)
    dest=Path(args.out);dest.parent.mkdir(parents=True,exist_ok=True)
    dest.write_text(json.dumps(result,indent=2,sort_keys=True)+"\n",encoding="utf-8")
    print("R50_ANDROID_APP_VERDICT="+result["classification"])
    print("R50_ANDROID_APP_REASON="+result["reason"])
    print("R50_ANDROID_APP_TEST_CERT_DISPOSABLE_ONLY=PASS")
    print("R50_ANDROID_PHYSICAL_APP_BACKGROUND_ENROLLMENT=NOT_TESTED")
    return 0 if result["classification"]=="SUPPORTED" else 1
if __name__=="__main__":raise SystemExit(main())
