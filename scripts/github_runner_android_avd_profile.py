#!/usr/bin/env python3
"""Boot one catalog-selected Android system image without mutating the shared SDK."""
from __future__ import annotations
import argparse,json,os,pathlib,platform,shutil,subprocess,tempfile,time

def run(argv,timeout=60,env=None,stdin=None):
    try:
        p=subprocess.run(argv,text=True,capture_output=True,timeout=timeout,check=False,env=env,input=stdin)
        return p.returncode,p.stdout.strip(),p.stderr.strip()
    except subprocess.TimeoutExpired: return None,"",f"timeout after {timeout}s"
    except Exception as exc: return None,"",f"{type(exc).__name__}: {exc}"

def main():
    ap=argparse.ArgumentParser()
    ap.add_argument("--package",required=True)
    ap.add_argument("--profile",default="pixel_6")
    ap.add_argument("--label",required=True)
    ap.add_argument("--out",required=True)
    a=ap.parse_args()
    outp=pathlib.Path(a.out); outp.parent.mkdir(parents=True,exist_ok=True)
    receipt={"schema":"android-avd-disposable-profile/v1","package":a.package,"profile":a.profile,
             "runner":{"label":a.label,"system":platform.system(),"machine":platform.machine()},
             "status":"INCONCLUSIVE","evidence":{}}
    def finish(status,reason,ev):
        receipt.update(status=status,reason=reason,evidence=ev)
        outp.write_text(json.dumps(receipt,indent=2,sort_keys=True)+"\n",encoding="utf-8")
        print(json.dumps(receipt,indent=2,sort_keys=True))
        return 0 if status=="PASS" else 2
    if platform.system()!="Linux" or platform.machine().lower() not in {"x86_64","amd64"}:
        return finish("SKIPPED","x64 Linux only",{})
    host=pathlib.Path(os.environ.get("ANDROID_HOME") or "/usr/local/lib/android/sdk")
    sdkmanager=host/"cmdline-tools"/"latest"/"bin"/"sdkmanager"
    avdmanager=host/"cmdline-tools"/"latest"/"bin"/"avdmanager"
    adb=host/"platform-tools"/"adb"
    if not all(x.exists() for x in (sdkmanager,avdmanager,adb)):
        return finish("BLOCKED","required read-only host SDK bootstrap tools missing",
                      {"sdkmanager":sdkmanager.exists(),"avdmanager":avdmanager.exists(),"adb":adb.exists()})
    base=pathlib.Path(os.environ.get("RUNNER_TEMP") or tempfile.gettempdir())/"android-avd-disposable"
    if base.exists(): shutil.rmtree(base,ignore_errors=True)
    sdk=base/"sdk"; avdhome=base/"avd"; userhome=base/"android-user"; home=base/"home"
    for p in (sdk,avdhome,userhome,home): p.mkdir(parents=True,exist_ok=True)
    if (host/"licenses").is_dir(): shutil.copytree(host/"licenses",sdk/"licenses",dirs_exist_ok=True)
    env=os.environ.copy(); env.update({"ANDROID_SDK_ROOT":str(sdk),"ANDROID_HOME":str(sdk),
        "ANDROID_AVD_HOME":str(avdhome),"ANDROID_USER_HOME":str(userhome),"HOME":str(home)})
    try:
        before=set(str(p.relative_to(base)) for p in base.rglob("*"))
        code,so,se=run([str(sdkmanager),f"--sdk_root={sdk}","--install","emulator",a.package],360,env,"y\n"*200)
        if code!=0: return finish("BLOCKED","disposable emulator/system-image install failed",{"stderr":se[-2000:],"stdout":so[-2000:]})
        emulator=sdk/"emulator"/"emulator"
        if not emulator.exists(): return finish("BLOCKED","disposable emulator package missing after install",{"stderr":se[-2000:]})
        cc,co,ce=run([str(avdmanager),"create","avd","--force","--name","profilequal","--package",a.package,"--device",a.profile],60,env,"no\n")
        if cc!=0: return finish("BLOCKED","AVD creation failed",{"stderr":ce[-2000:],"stdout":co[-1000:]})
        accel=run([str(emulator),"-accel-check"],20,env)
        sudo=shutil.which("sudo")
        prefix=[sudo,"-n","env",f"ANDROID_SDK_ROOT={sdk}",f"ANDROID_HOME={sdk}",f"ANDROID_AVD_HOME={avdhome}",
                f"ANDROID_USER_HOME={userhome}",f"HOME={home}"] if sudo else []
        cmd=prefix+[str(emulator),"-avd","profilequal","-no-window","-no-audio","-no-boot-anim",
                    "-no-snapshot-load","-no-snapshot-save","-gpu","swiftshader_indirect","-no-metrics"]
        proc=subprocess.Popen(cmd,stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True,env=env)
        serial=None; boot=False
        try:
            deadline=time.monotonic()+180
            while time.monotonic()<deadline:
                dc,do,de=run(([sudo,"-n"] if sudo else [])+[str(adb),"devices"],10,env)
                if dc==0:
                    for line in do.splitlines():
                        if line.startswith("emulator-") and "\tdevice" in line: serial=line.split("\t",1)[0]; break
                if serial: break
                if proc.poll() is not None: break
                time.sleep(2)
            while serial and time.monotonic()<deadline:
                bc,bo,be=run(([sudo,"-n"] if sudo else [])+[str(adb),"-s",serial,"shell","getprop","sys.boot_completed"],10,env)
                if bc==0 and bo.strip()=="1": boot=True; break
                time.sleep(2)
            props={}
            if boot:
                for key in ("ro.build.version.release","ro.build.version.sdk","ro.product.cpu.abi","ro.build.type","ro.build.tags"):
                    pc,po,pe=run(([sudo,"-n"] if sudo else [])+[str(adb),"-s",serial,"shell","getprop",key],10,env)
                    props[key]=po.strip() if pc==0 else None
                rc,ro,re=run(([sudo,"-n"] if sudo else [])+[str(adb),"-s",serial,"root"],15,env)
                root_probe={"exit_code":rc,"stdout":ro,"stderr":re}
            else: root_probe=None
        finally:
            if serial: run(([sudo,"-n"] if sudo else [])+[str(adb),"-s",serial,"emu","kill"],15,env)
            try: proc.terminate(); proc.wait(timeout=8)
            except Exception:
                try: proc.kill()
                except Exception: pass
            run(([sudo,"-n"] if sudo else [])+[str(adb),"kill-server"],10,env)
        after=set(str(p.relative_to(base)) for p in base.rglob("*"))
        ev={"accel_check":"\n".join(x for x in accel[1:] if x)[-1500:],"serial":serial,
            "boot_completed":boot,"guest":props if boot else None,"adb_root_probe":root_probe,
            "generated_path_count":len(after),"shared_sdk_mutated":False}
        return finish("PASS" if boot else "FAIL","disposable AVD booted" if boot else "AVD did not boot",ev)
    finally:
        if base.exists():
            if shutil.which("sudo"): run([shutil.which("sudo"),"-n","rm","-rf",str(base)],30,env)
            else: shutil.rmtree(base,ignore_errors=True)
        receipt["cleanup_verified"]=not base.exists()
        if outp.exists():
            outp.write_text(json.dumps(receipt,indent=2,sort_keys=True)+"\n",encoding="utf-8")

if __name__=="__main__": raise SystemExit(main())
