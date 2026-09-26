#!/usr/bin/env python3
"""Public-safe cross-platform AAR Android runtime converger."""
from __future__ import annotations
import argparse, hashlib, json, os, pathlib, platform, shutil, subprocess, time, urllib.request, zipfile
from typing import Any
SCHEMA="aar-runtime-qualification/v1"; API="35"; BUILD_TOOLS="35.0.0"; PLATFORM_TOOLS="37.0.1"; EMULATOR="37.1.11"; X86_IMAGE_REV="9"; ARM_IMAGE_REV="9"; AVD_NAME="aar-runtime-qual"
CLT={
 ("Windows","x86_64"):("https://dl.google.com/android/repository/commandlinetools-win-15859902_latest.zip","90ae805d20434428bffcb699c290860f19bb5f66a67e6b330067e3de801fb04a"),
 ("Linux","x86_64"):("https://dl.google.com/android/repository/commandlinetools-linux-15859902_latest.zip","4e4c464f145a7512b57d088ac6c278c03c9eea610886b35a5e0804e74eedf583"),
 ("Darwin","x86_64"):("https://dl.google.com/android/repository/commandlinetools-mac_x86_64-15859902_latest.zip","c5a6378ab5cf7e0d5701921405115befff13e9ff7417fb588389338f8bd050f3"),
 ("Darwin","arm64"):("https://dl.google.com/android/repository/commandlinetools-mac_arm64-15859902_latest.zip","835b62a26162b229b441d1f6d4680383815a270809eb33522c0d480fa5002c4e"),
}
def norm_arch(v): return {"amd64":"x86_64","x86_64":"x86_64","arm64":"arm64","aarch64":"arm64"}.get(v.lower(),v.lower())
def host(): return platform.system(),norm_arch(platform.machine())
def exe(name):
 if platform.system()=="Windows" and name in {"sdkmanager","avdmanager"}: return name+".bat"
 return name+".exe" if platform.system()=="Windows" else name
def run(argv,env=None,stdin=None,timeout=180):
 try:
  cp=subprocess.run(argv,input=stdin,text=True,capture_output=True,env=env,timeout=timeout,check=False,encoding="utf-8",errors="replace")
  return cp.returncode,cp.stdout,cp.stderr
 except subprocess.TimeoutExpired as e:
  out=e.stdout.decode("utf-8","replace") if isinstance(e.stdout,bytes) else (e.stdout or "")
  err=e.stderr.decode("utf-8","replace") if isinstance(e.stderr,bytes) else (e.stderr or "timeout")
  return 124,out,err
def sha256(path):
 h=hashlib.sha256()
 with path.open("rb") as f:
  for b in iter(lambda:f.read(8*1024*1024),b""): h.update(b)
 return h.hexdigest()
def safe_extract(src,dst):
 with zipfile.ZipFile(src) as z:
  for m in z.infolist():
   p=pathlib.PurePosixPath(m.filename)
   if p.is_absolute() or ".." in p.parts: raise RuntimeError("unsafe archive entry")
  z.extractall(dst)
def props(path):
 out={}
 if path.is_file():
  for line in path.read_text(encoding="utf-8",errors="replace").splitlines():
   if "=" in line and not line.lstrip().startswith("#"):
    k,v=line.split("=",1); out[k.strip()]=v.strip()
 return out
def paths(root):
 sdk=root/"sdk"; clt=sdk/"cmdline-tools"/"current"
 return {"sdk":sdk,"clt":clt,"sdkmanager":clt/"bin"/exe("sdkmanager"),"avdmanager":clt/"bin"/exe("avdmanager"),
  "adb":sdk/"platform-tools"/("adb.exe" if platform.system()=="Windows" else "adb"),
  "emulator":sdk/"emulator"/("emulator.exe" if platform.system()=="Windows" else "emulator"),
  "apksigner":sdk/"build-tools"/BUILD_TOOLS/("apksigner.bat" if platform.system()=="Windows" else "apksigner"),
  "avd_home":root/"avd","user_home":root/"android-user-home","manifest":root/"manifest.json"}
def image_package(system,arch):
 abi="arm64-v8a" if system=="Darwin" and arch=="arm64" else "x86_64"; return f"system-images;android-{API};google_apis_playstore;{abi}"
def image_dir(root,system,arch):
 abi="arm64-v8a" if system=="Darwin" and arch=="arm64" else "x86_64"; return root/"sdk"/"system-images"/f"android-{API}"/"google_apis_playstore"/abi
def environment(root):
 p=paths(root); e=os.environ.copy(); e.update({"ANDROID_HOME":str(p["sdk"]),"ANDROID_SDK_ROOT":str(p["sdk"]),"ANDROID_AVD_HOME":str(p["avd_home"]),"ANDROID_USER_HOME":str(p["user_home"]),"JAVA_TOOL_OPTIONS":"-Dfile.encoding=UTF-8"}); return e
def java_info():
 j=shutil.which("java")
 if not j:return {"present":False}
 c,o,e=run([j,"-version"],timeout=20); return {"present":c==0,"path":j,"version":(e or o).splitlines()[0] if (e or o) else None}
def revisions(root,system,arch):
 p=paths(root); img=image_dir(root,system,arch)
 return {"platform_tools":props(p["sdk"]/"platform-tools"/"source.properties").get("Pkg.Revision"),"emulator":props(p["sdk"]/"emulator"/"source.properties").get("Pkg.Revision"),"build_tools":props(p["sdk"]/"build-tools"/BUILD_TOOLS/"source.properties").get("Pkg.Revision"),"system_image":props(img/"source.properties").get("Pkg.Revision"),"system_image_abi":props(img/"source.properties").get("SystemImage.Abi")}
def observe(root):
 system,arch=host(); p=paths(root); supported=(system,arch) in CLT; virt={"backend":{"Linux":"KVM","Windows":"WHPX","Darwin":"Hypervisor.Framework"}.get(system),"status":"not_checked"}
 if system=="Linux":
  k=pathlib.Path("/dev/kvm"); virt.update({"device":"/dev/kvm","exists":k.exists(),"readable":os.access(k,os.R_OK),"writable":os.access(k,os.W_OK)})
 if p["emulator"].is_file():
  c,o,e=run([str(p["emulator"]),"-accel-check"],env=environment(root),timeout=30); virt.update({"status":"usable" if c==0 and "usable" in (o+e).lower() else "unavailable","exit_code":c,"evidence":(o+e)[-1200:]})
 return {"schema":SCHEMA,"operation":"status","host":{"system":system,"architecture":arch,"supported":supported,"runner_name":os.environ.get("RUNNER_NAME"),"runner_arch":os.environ.get("RUNNER_ARCH"),"image_os":os.environ.get("ImageOS"),"image_version":os.environ.get("ImageVersion")},"root":str(root),"java":java_info(),"tools":{k:v.is_file() for k,v in p.items() if k in {"sdkmanager","avdmanager","adb","emulator","apksigner"}},"revisions":revisions(root,system,arch),"image_package":image_package(system,arch) if supported else None,"manifest_present":p["manifest"].is_file(),"virtualization":virt}
def desired_ok(obs):
 s=obs["host"]["system"]; a=obs["host"]["architecture"]; er=ARM_IMAGE_REV if s=="Darwin" and a=="arm64" else X86_IMAGE_REV; r=obs["revisions"]
 return bool(obs["host"]["supported"] and obs["java"]["present"] and all(obs["tools"].values()) and r["platform_tools"]==PLATFORM_TOOLS and r["emulator"]==EMULATOR and r["build_tools"]==BUILD_TOOLS and r["system_image"]==er and obs["manifest_present"])
def plan(root):
 o=observe(root)
 if not o["host"]["supported"]: return {"schema":SCHEMA,"operation":"plan","action":"unsupported_host","changed":False,"observation":o}
 return {"schema":SCHEMA,"operation":"plan","action":"noop" if desired_ok(o) else "install-or-repair","changed":not desired_ok(o),"desired":{"platform_tools":PLATFORM_TOOLS,"emulator":EMULATOR,"build_tools":BUILD_TOOLS,"system_image_revision":ARM_IMAGE_REV if o["host"]["system"]=="Darwin" and o["host"]["architecture"]=="arm64" else X86_IMAGE_REV,"image_package":o["image_package"]},"observation":o}
def bootstrap(root):
 system,arch=host(); url,expected=CLT[(system,arch)]; p=paths(root); p["sdk"].mkdir(parents=True,exist_ok=True); cache=root/"cache"; cache.mkdir(parents=True,exist_ok=True); arc=cache/"clt.zip"
 if not arc.is_file() or sha256(arc)!=expected:
  part=arc.with_suffix(".part"); req=urllib.request.Request(url,headers={"User-Agent":"AAR-runtime-qualification/1"})
  with urllib.request.urlopen(req,timeout=120) as resp,part.open("wb") as f: shutil.copyfileobj(resp,f)
  got=sha256(part)
  if got!=expected: part.unlink(missing_ok=True); raise RuntimeError(f"command-line tools SHA-256 mismatch: {got}")
  part.replace(arc)
 stage=root/"stage-clt"; shutil.rmtree(stage,ignore_errors=True); stage.mkdir(); safe_extract(arc,stage)
 candidates=[x.parent.parent for x in stage.rglob(exe("sdkmanager")) if (x.parent/exe("avdmanager")).is_file()]
 if len(candidates)!=1: raise RuntimeError(f"command-line tools root ambiguity: {len(candidates)}")
 dest=p["clt"]; shutil.rmtree(dest,ignore_errors=True); dest.parent.mkdir(parents=True,exist_ok=True); shutil.copytree(candidates[0],dest); shutil.rmtree(stage,ignore_errors=True)
 if system!="Windows":
  for x in (dest/"bin").iterdir():
   if x.is_file(): x.chmod(x.stat().st_mode|0o111)
 return {"url":url,"sha256":expected}
def install_packages(root):
 p=paths(root); env=environment(root); licenses="y\n"*300; run([str(p["sdkmanager"]),"--sdk_root="+str(p["sdk"]),"--licenses"],env=env,stdin=licenses,timeout=240)
 pkgs=["platform-tools","emulator",f"build-tools;{BUILD_TOOLS}",image_package(*host())]; c,o,e=run([str(p["sdkmanager"]),"--sdk_root="+str(p["sdk"]),"--install",*pkgs],env=env,stdin=licenses,timeout=720)
 if c!=0: raise RuntimeError(f"sdkmanager install failed {c}: {(e or o)[-1600:]}")
 return pkgs
def create_avd(root):
 p=paths(root); env=environment(root); p["avd_home"].mkdir(parents=True,exist_ok=True); p["user_home"].mkdir(parents=True,exist_ok=True)
 if (p["avd_home"]/(AVD_NAME+".ini")).is_file() and (p["avd_home"]/(AVD_NAME+".avd")).is_dir(): return False
 c,o,e=run([str(p["avdmanager"]),"create","avd","--force","--name",AVD_NAME,"--package",image_package(*host()),"--device","pixel_7"],env=env,stdin="no\n",timeout=90)
 if c!=0: raise RuntimeError(f"AVD create failed {c}: {(e or o)[-1600:]}")
 return True
def can_elevate_kvm():
 if platform.system()!="Linux" or not pathlib.Path("/dev/kvm").exists(): return False
 sudo=shutil.which("sudo")
 if not sudo: return False
 code,_,_=run([sudo,"-n","test","-r","/dev/kvm"],timeout=10)
 code2,_,_=run([sudo,"-n","test","-w","/dev/kvm"],timeout=10)
 return code==0 and code2==0

def emulator_command(root,accel):
 p=paths(root); env=environment(root)
 args=[str(p["emulator"]),"-avd",AVD_NAME,"-port","5556","-no-window","-no-audio","-no-boot-anim","-no-snapshot-load","-no-snapshot-save","-gpu","swiftshader_indirect","-no-metrics",*accel]
 elevated=False
 if platform.system()=="Linux" and pathlib.Path("/dev/kvm").exists() and not os.access("/dev/kvm",os.W_OK):
  sudo=shutil.which("sudo")
  if sudo:
   env_args=[f"{k}={env[k]}" for k in ("ANDROID_HOME","ANDROID_SDK_ROOT","ANDROID_AVD_HOME","ANDROID_USER_HOME","HOME") if k in env]
   args=[sudo,"-n","env",*env_args,*args]; elevated=True
 return args,elevated

def restore_managed_ownership(root):
 if platform.system()!="Linux" or not hasattr(os,"getuid"): return
 sudo=shutil.which("sudo")
 if not sudo:return
 uid=os.getuid(); gid=os.getgid()
 run([sudo,"-n","chown","-R",f"{uid}:{gid}",str(root)],timeout=60)

def stop_emulator(proc,adb,serial,env,avd_root):
 if serial:
  run([str(adb),"-s",serial,"emu","kill"],env=env,timeout=20)
 try:
  proc.wait(timeout=20)
 except Exception:
  if platform.system()=="Windows":
   taskkill=shutil.which("taskkill")
   if taskkill: run([taskkill,"/PID",str(proc.pid),"/T","/F"],timeout=30)
  else:
   try: proc.terminate(); proc.wait(timeout=8)
   except Exception:
    try: proc.kill()
    except Exception: pass
 run([str(adb),"kill-server"],env=env,timeout=15)
 deadline=time.monotonic()+30
 while time.monotonic()<deadline:
  locks=list(avd_root.rglob("*.lock"))+list(avd_root.rglob("*.lock/*"))
  if not any(x.exists() for x in locks): break
  time.sleep(1)

def verify(root,boot=True):
 o=observe(root); base=desired_ok(o); r={"schema":SCHEMA,"operation":"verify","base_ready":base,"boot_requested":boot,"passed":False,"observation":o}
 if not base:return r
 if not boot:r.update({"passed":True,"classification":"TOOLS_READY"}); return r
 p=paths(root); env=environment(root); create_avd(root); native=o["virtualization"].get("status")=="usable" or can_elevate_kvm(); attempts=[("native",["-accel","on"])] if native else []; attempts.append(("software",["-accel","off"])); records=[]
 for mode,accel in attempts:
  cmd,elevated=emulator_command(root,accel)
  proc=subprocess.Popen(cmd,stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True,encoding="utf-8",errors="replace",env=env)
  serial="emulator-5556"; booted=False; start=time.monotonic()
  try:
   deadline=time.monotonic()+(180 if mode=="native" else 300)
   while time.monotonic()<deadline and proc.poll() is None:
    c,o2,e=run([str(p["adb"]),"devices"],env=env,timeout=10)
    if c==0 and any(ln.startswith(serial+"\tdevice") for ln in o2.splitlines()):
     c,o2,e=run([str(p["adb"]),"-s",serial,"shell","getprop","sys.boot_completed"],env=env,timeout=10)
     if c==0 and o2.strip()=="1": booted=True; break
    time.sleep(2)
   play=False; api=None; abi=None
   if booted:
    c,o2,e=run([str(p["adb"]),"-s",serial,"shell","pm","path","com.android.vending"],env=env,timeout=20); play=c==0 and "package:" in o2
    _,api,_=run([str(p["adb"]),"-s",serial,"shell","getprop","ro.build.version.sdk"],env=env,timeout=10); _,abi,_=run([str(p["adb"]),"-s",serial,"shell","getprop","ro.product.cpu.abi"],env=env,timeout=10)
   records.append({"mode":mode,"boot_completed":booted,"play_store_present":play if booted else False,"api":(api or "").strip() or None,"abi":(abi or "").strip() or None,"elapsed_seconds":round(time.monotonic()-start,2),"exit_code":proc.poll()})
   if booted and play:r.update({"passed":True,"classification":"LIVE_READY","boot":records}); return r
  finally:
   stop_emulator(proc,p["adb"],serial,env,p["avd_home"])
   if elevated: restore_managed_ownership(root)
 r.update({"classification":"VENUE_ACCELERATION_UNAVAILABLE" if not native else "BOOT_FAILED","boot":records}); return r
def apply(root):
 p=plan(root)
 if p["action"]=="unsupported_host": raise RuntimeError("unsupported_host")
 changed=False; comps={}
 if p["changed"]:
  root.mkdir(parents=True,exist_ok=True); comps["command_line_tools"]=bootstrap(root); comps["sdk_packages"]=install_packages(root); create_avd(root); changed=True
  paths(root)["manifest"].write_text(json.dumps({"schema":SCHEMA,"host":{"system":host()[0],"architecture":host()[1]},"desired":p["desired"],"components":comps},indent=2,sort_keys=True)+"\n",encoding="utf-8")
 v=verify(root,boot=False)
 if not v["passed"]: raise RuntimeError("post-apply tool verification failed")
 return {"schema":SCHEMA,"operation":"apply","changed":changed,"plan":p,"verification":v}
def revert(root):
 existed=root.exists()
 if existed:
  rr=root.resolve()
  if rr==pathlib.Path.home().resolve() or len(rr.parts)<3: raise RuntimeError("unsafe managed root")
  shutil.rmtree(root)
 return {"schema":SCHEMA,"operation":"revert","changed":existed,"passed":not root.exists()}
def cycle(root):
 before=observe(root); p1=plan(root); a1=apply(root); v1=verify(root,True); p2=plan(root); a2=apply(root); v2=verify(root,False); rv=revert(root); a3=apply(root); v3=verify(root,True)
 passed=bool(v1["passed"] and p2["action"]=="noop" and not a2["changed"] and v2["passed"] and rv["passed"] and a3["changed"] and v3["passed"])
 return {"schema":SCHEMA,"operation":"cycle","passed":passed,"before":before,"first_plan":p1,"first_apply":a1,"first_verify":v1,"second_plan":p2,"second_apply":a2,"second_verify":v2,"revert":rv,"reapply":a3,"final_verify":v3}
def contract():
 return {"schema":SCHEMA,"audiences":{"human":{"commands":["status","plan","apply","verify","revert","cycle"],"default_output":"human"},"automation":{"output":"json","success_signal":"passed","idempotence_signal":"changed"},"agent":{"discover":"contract","observe":"status","plan":"plan","mutate":["apply","revert"],"verify":"verify","preferred_output":"json"}},"lifecycle":"observe -> plan -> apply -> verify","properties":["project-local","repeatable","reversible","idempotent","fail-closed"],"supported_hosts":[{"system":k[0],"architecture":k[1]} for k in CLT]}
def human(v):
 op=v.get("operation")
 if op=="status": return f"status: {v['host']['system']}/{v['host']['architecture']} supported={v['host']['supported']} ready={desired_ok(v)}"
 if op=="plan": return f"plan: {v['action']} changed={v['changed']}"
 if op=="apply": return f"apply: {'changed' if v['changed'] else 'no-op'}"
 if op=="verify": return f"verify: {'PASS' if v.get('passed') else 'FAIL'} {v.get('classification','')}"
 if op=="revert": return f"revert: {'PASS' if v.get('passed') else 'FAIL'} changed={v.get('changed')}"
 if op=="cycle": return f"cycle: {'PASS' if v.get('passed') else 'FAIL'}"
 return json.dumps(v,indent=2,sort_keys=True)
def main():
 ap=argparse.ArgumentParser(); ap.add_argument("command",choices=["status","plan","apply","verify","revert","cycle","contract"]); ap.add_argument("--root",type=pathlib.Path); ap.add_argument("--output",choices=["human","json"],default="human"); ap.add_argument("--no-boot",action="store_true"); a=ap.parse_args(); root=(a.root or pathlib.Path.cwd()/".local"/"aar-runtime").resolve()
 try:
  v=observe(root) if a.command=="status" else plan(root) if a.command=="plan" else apply(root) if a.command=="apply" else verify(root,not a.no_boot) if a.command=="verify" else revert(root) if a.command=="revert" else cycle(root) if a.command=="cycle" else contract()
 except Exception as e:v={"schema":SCHEMA,"operation":a.command,"passed":False,"classification":"HARNESS_FAILURE","error":f"{type(e).__name__}: {e}"}
 print(json.dumps(v,indent=2,sort_keys=True) if a.output=="json" else human(v)); return 0 if (a.command not in {"verify","revert","cycle"} or v.get("passed")) else 2
if __name__=="__main__": raise SystemExit(main())
