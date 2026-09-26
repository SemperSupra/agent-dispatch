#!/usr/bin/env python3
"""Read-only catalog census for Android system images usable by hosted x64 runners."""
from __future__ import annotations
import argparse, json, os, pathlib, platform, re, subprocess

PATTERN=re.compile(r"^system-images;([^;]+);([^;]+);([^;]+)$")

def run(argv,timeout=120):
    try:
        p=subprocess.run(argv,text=True,capture_output=True,timeout=timeout,check=False)
        return p.returncode,p.stdout,p.stderr
    except Exception as exc:
        return None,"",f"{type(exc).__name__}: {exc}"

def main():
    ap=argparse.ArgumentParser()
    ap.add_argument("--label",required=True)
    ap.add_argument("--out",required=True)
    a=ap.parse_args()
    root=os.environ.get("ANDROID_HOME") or os.environ.get("ANDROID_SDK_ROOT") or "/usr/local/lib/android/sdk"
    sdk=pathlib.Path(root)
    manager=sdk/"cmdline-tools"/"latest"/"bin"/"sdkmanager"
    rec={"schema":"android-avd-catalog-census/v1","runner":{"label":a.label,"system":platform.system(),"machine":platform.machine()},
         "sdk_root":str(sdk),"catalog":[],"families":{},"status":"INCONCLUSIVE","reason":None}
    if platform.system()!="Linux" or platform.machine().lower() not in {"x86_64","amd64"}:
        rec.update(status="SKIPPED",reason="hosted AVD census currently limited to x64 Linux")
    elif not manager.exists():
        rec.update(status="BLOCKED",reason="sdkmanager missing")
    else:
        code,out,err=run([str(manager),"--list"],180)
        if code!=0:
            rec.update(status="BLOCKED",reason="sdkmanager --list failed",stderr=err[-2000:])
        else:
            seen=set()
            for line in out.splitlines():
                token=line.strip().split("|",1)[0].strip()
                m=PATTERN.match(token)
                if not m or token in seen: continue
                seen.add(token)
                api,tag,abi=m.groups()
                if abi not in {"x86_64","x86"}: continue
                item={"package":token,"api":api,"tag":tag,"abi":abi}
                rec["catalog"].append(item)
                rec["families"].setdefault(tag,[]).append(api)
            rec["catalog"].sort(key=lambda x:x["package"])
            for k in list(rec["families"]): rec["families"][k]=sorted(set(rec["families"][k]))
            rec.update(status="PASS",reason="catalog enumerated without SDK mutation",count=len(rec["catalog"]))
    outp=pathlib.Path(a.out); outp.parent.mkdir(parents=True,exist_ok=True)
    outp.write_text(json.dumps(rec,indent=2,sort_keys=True)+"\n",encoding="utf-8")
    print(json.dumps(rec,indent=2,sort_keys=True))
    return 0 if rec["status"]=="PASS" else 2

if __name__=="__main__": raise SystemExit(main())
