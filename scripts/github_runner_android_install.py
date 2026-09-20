#!/usr/bin/env python3
"""Bounded Android emulator setup-cost + boot qualification for ubuntu-26.04 x64."""
from __future__ import annotations
import argparse,json,os,pathlib,platform,shutil,subprocess,tempfile,time

PKGS=["emulator","system-images;android-35;google_apis;x86_64"]

def run(argv,timeout=60,env=None,stdin=None):
    try:
        cp=subprocess.run(argv,check=False,capture_output=True,text=True,timeout=timeout,env=env,input=stdin)
        return cp.returncode,cp.stdout.strip(),cp.stderr.strip()
    except subprocess.TimeoutExpired:
        return None,"",f"timeout after {timeout}s"
    except Exception as exc:
        return None,"",str(exc)

def main():
    p=argparse.ArgumentParser();p.add_argument("--label",required=True);p.add_argument("--out",required=True)
    a=p.parse_args()
    receipt={
      "schema":"github-runner-android-setup-qualification/v1",
      "provenance":{"requested_label":a.label,"workflow_sha":os.environ.get("GITHUB_SHA",""),
        "run_id":os.environ.get("GITHUB_RUN_ID",""),"run_attempt":os.environ.get("GITHUB_RUN_ATTEMPT",""),
        "image_os":os.environ.get("ImageOS"),"image_version":os.environ.get("ImageVersion")},
      "runner":{"system":platform.system(),"machine":platform.machine()},
      "setup":{"packages":PKGS},
      "result":{"classification":"INCONCLUSIVE","passed":False,"reason":"not executed","evidence":{}},
      "warnings":["network package installation is part of this representative setup-cost workload",
                  "qualification is exact-image/workload evidence, not a service guarantee"]
    }
    def finish(cls,passed,reason,ev):
        receipt["result"]={"classification":cls,"passed":passed,"reason":reason,"evidence":ev}
        out=pathlib.Path(a.out);out.parent.mkdir(parents=True,exist_ok=True)
        out.write_text(json.dumps(receipt,indent=2,sort_keys=True)+"\n",encoding="utf-8")
        print("ANDROID_INSTALL_RECEIPT="+str(out));print(json.dumps(receipt,indent=2,sort_keys=True))
        return 0
    if platform.system()!="Linux" or platform.machine() not in {"x86_64","amd64"}:
        return finish("SKIPPED_GUARDRAIL",False,"x86_64 Linux-only workload",{})
    if a.label!="ubuntu-26.04":
        return finish("SKIPPED_GUARDRAIL",False,"first setup-cost rep intentionally limited to ubuntu-26.04",{})
    sdk=pathlib.Path(os.environ.get("ANDROID_HOME") or "/usr/local/lib/android/sdk")
    sdkmanager=sdk/"cmdline-tools"/"latest"/"bin"/"sdkmanager"
    avdmanager=sdk/"cmdline-tools"/"latest"/"bin"/"avdmanager"
    adb=sdk/"platform-tools"/"adb"
    sudo=shutil.which("sudo")
    if not all([sdkmanager.exists(),avdmanager.exists(),adb.exists(),sudo]):
        return finish("SKIPPED_GUARDRAIL",False,"preinstalled SDK management entry gate failed",
                      {"sdkmanager":sdkmanager.exists(),"avdmanager":avdmanager.exists(),
                       "adb":adb.exists(),"sudo":bool(sudo)})
    before=shutil.disk_usage(sdk)
    started=time.monotonic()
    code,out,err=run([sudo,"-n",str(sdkmanager),"--install",*PKGS],timeout=360,stdin=("y\n"*200))
    install_s=time.monotonic()-started
    after=shutil.disk_usage(sdk)
    install_ev={"exit_code":code,"elapsed_seconds":round(install_s,3),
                "used_bytes_delta":(after.used-before.used),
                "free_bytes_before":before.free,"free_bytes_after":after.free,
                "stdout_tail":out[-1500:] if out else None,"stderr_tail":err[-1500:] if err else None}
    emulator=sdk/"emulator"/"emulator"
    image=sdk/"system-images"/"android-35"/"google_apis"/"x86_64"
    if code!=0 or not emulator.exists() or not image.is_dir():
        return finish("ENVIRONMENT_FAILURE",False,"bounded Android SDK package installation did not satisfy entry gate",
                      {**install_ev,"emulator_present":emulator.exists(),"system_image_present":image.is_dir()})
    with tempfile.TemporaryDirectory(prefix="runner-android-install-") as td:
        root=pathlib.Path(td); avd_home=root/"avd"; avd_home.mkdir(); home=root/"home";home.mkdir()
        env=os.environ.copy();env.update({"ANDROID_AVD_HOME":str(avd_home),"ANDROID_USER_HOME":str(root/"android-home"),"HOME":str(home)})
        pathlib.Path(env["ANDROID_USER_HOME"]).mkdir()
        create_code,create_out,create_err=run([str(avdmanager),"create","avd","--force","--name","installqual",
            "--package",PKGS[1],"--device","pixel_6"],timeout=30,env=env,stdin="no\n")
        if create_code!=0:
            return finish("HARNESS_FAILURE",False,"AVD creation failed after package installation",
                          {**install_ev,"create_exit":create_code,"create_stderr":create_err[-1200:]})
        accel_code,accel_out,accel_err=run([sudo,"-n",str(emulator),"-accel-check"],timeout=20,env=env)
        if accel_code!=0:
            return finish("ORACLE_FAILURE",False,"emulator acceleration check failed after installation",
                          {**install_ev,"accel_exit":accel_code,
                           "accel_output":(accel_out+"\n"+accel_err)[-1500:]})
        cmd=[sudo,"-n","env",f"ANDROID_AVD_HOME={avd_home}",f"ANDROID_USER_HOME={env['ANDROID_USER_HOME']}",
             f"HOME={home}",str(emulator),"-avd","installqual","-no-window","-no-audio","-no-boot-anim",
             "-no-snapshot-load","-no-snapshot-save","-accel","on","-gpu","swiftshader_indirect","-no-metrics"]
        proc=subprocess.Popen(cmd,stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True,env=env)
        serial=None;boot="";boot_start=time.monotonic();last_err=""
        try:
            deadline=time.monotonic()+150
            while time.monotonic()<deadline:
                c,o,e=run([sudo,"-n",str(adb),"devices"],timeout=10,env=env)
                if c==0:
                    for line in o.splitlines():
                        if line.startswith("emulator-") and "\tdevice" in line:
                            serial=line.split("\t",1)[0];break
                if serial or proc.poll() is not None: break
                time.sleep(2)
            if serial:
                while time.monotonic()<deadline:
                    c,o,e=run([sudo,"-n",str(adb),"-s",serial,"shell","getprop","sys.boot_completed"],timeout=10,env=env)
                    if c==0 and o.strip()=="1": boot="1";break
                    last_err=e;time.sleep(2)
            boot_s=time.monotonic()-boot_start
            qcode,qout,qerr=(None,"","")
            if boot=="1":
                qcode,qout,qerr=run([sudo,"-n",str(adb),"-s",serial,"shell","getprop","ro.product.cpu.abi"],timeout=10,env=env)
            passed=boot=="1" and qcode==0
        finally:
            if serial: run([sudo,"-n",str(adb),"-s",serial,"emu","kill"],timeout=15,env=env)
            try: proc.terminate();proc.wait(timeout=8)
            except Exception:
                try: proc.kill()
                except Exception: pass
            run([sudo,"-n",str(adb),"kill-server"],timeout=10,env=env)
        ev={**install_ev,"accel_check":(accel_out+"\n"+accel_err).strip()[-1500:],
            "serial":serial,"boot_completed":boot or None,"boot_elapsed_seconds":round(boot_s,3),
            "guest_abi":qout.strip() if qcode==0 else None,"adb_error":last_err[-800:] or None}
        return finish("SUPPORTED" if passed else "ORACLE_FAILURE",passed,
                      "installed emulator + system image and booted disposable accelerated AVD" if passed
                      else "installed Android components but disposable AVD did not complete boot",ev)

if __name__=="__main__": raise SystemExit(main())
