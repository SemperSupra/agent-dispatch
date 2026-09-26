#!/usr/bin/env python3
"""Host + target capability lifecycle for unknown devices.

Read-only discovery is generic. A plan is created only from explicitly requested
primitives. Generated state lives under .android-edge-local/ unless overridden.
"""
from __future__ import annotations
import argparse,json,os,pathlib,platform,shutil,subprocess,time
from typing import Any

SCHEMA="android-edge-device-capabilities/v1"

def repo_root()->pathlib.Path:
    return pathlib.Path(__file__).resolve().parents[1]
def default_state_root()->pathlib.Path:
    return repo_root()/".android-edge-local"
def run(argv:list[str],timeout=10)->dict[str,Any]:
    try:
        p=subprocess.run(argv,text=True,capture_output=True,timeout=timeout,check=False)
        return {"command":argv,"returncode":p.returncode,"stdout":p.stdout.strip(),"stderr":p.stderr.strip()}
    except Exception as exc:
        return {"command":argv,"returncode":None,"stdout":"","stderr":f"{type(exc).__name__}: {exc}"}
def dump(root:pathlib.Path,name:str,value:dict[str,Any]):
    root.mkdir(parents=True,exist_ok=True)
    (root/f"{name}.json").write_text(json.dumps(value,indent=2,sort_keys=True)+"\n",encoding="utf-8")

def _which(names:list[str])->dict[str,str|None]:
    return {n:shutil.which(n) for n in names}

def _adb_targets(adb:str|None)->list[dict[str,Any]]:
    if not adb:return []
    r=run([adb,"devices","-l"])
    out=[]
    if r["returncode"]==0:
        for line in r["stdout"].splitlines()[1:]:
            if not line.strip():continue
            parts=line.split()
            if len(parts)<2:continue
            item={"transport":"adb","id":parts[0],"state":parts[1],"details":parts[2:]}
            out.append(item)
    return out

def _fastboot_targets(fastboot:str|None)->list[dict[str,Any]]:
    if not fastboot:return []
    r=run([fastboot,"devices"])
    out=[]
    if r["returncode"]==0:
        for line in r["stdout"].splitlines():
            p=line.split()
            if p:out.append({"transport":"fastboot","id":p[0],"state":p[1] if len(p)>1 else None})
    return out

def _linux_usb_access()->dict[str,Any]:
    root=pathlib.Path("/dev/bus/usb")
    return {"usbfs_present":root.is_dir(),"usbfs_readable":os.access(root,os.R_OK) if root.exists() else False,
            "usbfs_writable":os.access(root,os.W_OK) if root.exists() else False}

def discover(root:pathlib.Path)->dict[str,Any]:
    system=platform.system()
    commands=_which(["adb","fastboot","python3","python","pwsh","powershell","bluetoothctl","system_profiler"])
    host={"system":system,"release":platform.release(),"machine":platform.machine(),"commands":commands}
    if system=="Windows":
        host["usb_backend"]={"kind":"WinUSB/vendor-driver","google_driver_store":"discover-via-host-converger"}
        host["ble_backend"]="WinRT"
    elif system=="Linux":
        host["usb_backend"]={"kind":"usbfs/kernel","access":_linux_usb_access()}
        host["ble_backend"]="BlueZ/D-Bus"
    elif system=="Darwin":
        host["usb_backend"]={"kind":"IOKit/native","additional_driver_required":False}
        host["ble_backend"]="CoreBluetooth"
    else:
        host["usb_backend"]={"kind":"unknown"}
        host["ble_backend"]=None
    targets=_adb_targets(commands["adb"])+_fastboot_targets(commands["fastboot"])
    value={"schema":SCHEMA,"phase":"discover","timestamp_unix":int(time.time()),"host":host,"targets":targets,
           "invariants":["read-only discovery","no target identity assumptions","no host mutation"]}
    dump(root,"discover",value);return value

HOST_ADAPTERS={
 "adb":{"tool":"adb","provider":"Android Platform-Tools","acquire":"host-converger","target_transport":"adb"},
 "fastboot":{"tool":"fastboot","provider":"Android Platform-Tools","acquire":"host-converger","target_transport":"fastboot"},
 "usb-android":{"tool":None,"provider":"native USB / WinUSB","acquire":"host-specific","target_transport":"usb"},
 "ble":{"tool":None,"provider":"Bleak + native OS backend","acquire":"project-local-python","target_transport":"ble"},
}

def plan(root:pathlib.Path,required:list[str])->dict[str,Any]:
    d=discover(root); system=d["host"]["system"]; cmds=d["host"]["commands"]; steps=[]; blockers=[]
    for primitive in required:
        spec=HOST_ADAPTERS.get(primitive)
        if not spec:
            blockers.append({"primitive":primitive,"reason":"unknown primitive; no adapter contract"})
            continue
        if primitive in {"adb","fastboot"}:
            present=bool(cmds.get(spec["tool"]))
            steps.append({"primitive":primitive,"status":"ready" if present else "acquire",
                          "provider":spec["provider"],"method":"tools/android_edge_host_converge.py apply" if not present else None})
        elif primitive=="usb-android":
            if system=="Windows":
                steps.append({"primitive":primitive,"status":"verify-driver","provider":"Google USB Driver r13 / WinUSB",
                              "method":"tools/android_edge_host_converge.py verify"})
            elif system in {"Linux","Darwin"}:
                steps.append({"primitive":primitive,"status":"ready-or-permission-check","provider":spec["provider"],
                              "method":"no kernel/system driver installation by this project"})
            else:blockers.append({"primitive":primitive,"reason":f"unsupported host OS {system}"})
        elif primitive=="ble":
            provider={"Windows":"Bleak/WinRT","Linux":"Bleak/BlueZ","Darwin":"Bleak/CoreBluetooth"}.get(system)
            if provider:steps.append({"primitive":primitive,"status":"acquire-project-local","provider":provider,
                                      "method":"project-local virtual environment; no service/driver mutation"})
            else:blockers.append({"primitive":primitive,"reason":f"unsupported host OS {system}"})
    value={"schema":SCHEMA,"phase":"plan","timestamp_unix":int(time.time()),"required":required,
           "steps":steps,"blockers":blockers,"apply_allowed":not blockers,
           "state_root":str(root),"safety":["generated state only under state_root","no sudo/system package manager",
             "no driver/service/privacy mutation unless separately explicit and reversible","target mutations require a later use-case-specific plan"]}
    dump(root,"plan",value);return value

def verify(root:pathlib.Path,required:list[str])->dict[str,Any]:
    d=discover(root);cmds=d["host"]["commands"];checks={};passed=True
    for primitive in required:
        if primitive in {"adb","fastboot"}:
            ok=bool(cmds.get(primitive));checks[primitive]={"passed":ok,"path":cmds.get(primitive)};passed &= ok
        elif primitive=="usb-android":
            ok=d["host"]["system"] in {"Windows","Linux","Darwin"};checks[primitive]={"passed":ok,"backend":d["host"]["usb_backend"]};passed &= ok
        elif primitive=="ble":
            ok=d["host"]["ble_backend"] is not None;checks[primitive]={"passed":ok,"backend":d["host"]["ble_backend"]};passed &= ok
        else:checks[primitive]={"passed":False,"reason":"unknown primitive"};passed=False
    value={"schema":SCHEMA,"phase":"verify","timestamp_unix":int(time.time()),"passed":bool(passed),"checks":checks,
           "targets":d["targets"]}
    dump(root,"verify",value);return value

def contract()->dict[str,Any]:
    return {"schema":SCHEMA,"audiences":{
      "human":{"entry":"python tools/device_capability_lifecycle.py discover|plan|verify|clean","output":"human or JSON receipts"},
      "automation":{"receipts":["discover.json","plan.json","verify.json"],"success":"verify.passed","stable_schema":SCHEMA},
      "agent":{"discover":"discover","plan":"plan --require <primitive>","verify":"verify --require <primitive>","mutate":"delegated adapters only"}},
      "primitives":HOST_ADAPTERS,
      "lifecycle":["discover","plan","apply-by-adapter","verify"],"state":"project-local disposable"}

def main():
    ap=argparse.ArgumentParser();ap.add_argument("--state-root",type=pathlib.Path,default=default_state_root())
    sp=ap.add_subparsers(dest="op",required=True)
    for n in ("discover","contract","clean"):sp.add_parser(n)
    for n in ("plan","verify"):
        p=sp.add_parser(n);p.add_argument("--require",action="append",default=[],required=True)
    a=ap.parse_args()
    if a.op=="clean":
        existed=a.state_root.exists();shutil.rmtree(a.state_root,ignore_errors=True);v={"schema":SCHEMA,"phase":"clean","passed":not a.state_root.exists(),"existed":existed}
    elif a.op=="contract":v=contract()
    elif a.op=="discover":v=discover(a.state_root)
    elif a.op=="plan":v=plan(a.state_root,a.require)
    else:v=verify(a.state_root,a.require)
    print(json.dumps(v,indent=2,sort_keys=True))
    return 0 if not (a.op=="verify" and not v["passed"]) else 2

if __name__=="__main__":raise SystemExit(main())
