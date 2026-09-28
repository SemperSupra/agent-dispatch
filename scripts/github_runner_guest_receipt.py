#!/usr/bin/env python3
import argparse, datetime as dt, json, os, pathlib

def intval(v):
    try: return int(v) if v else None
    except (TypeError, ValueError): return None

def parse(path):
    values={}
    for line in pathlib.Path(path).read_text(errors="replace").splitlines():
        if "=" in line:
            k,v=line.split("=",1); values[k]=v
    return values

def capability(name, ok, reason, evidence=None):
    return {"name":name,"advertised":None,"observed":ok,"installed":None,
      "callable":ok,"exercised":True,"oracleSatisfied":ok,
      "classification":"SUPPORTED" if ok else "ORACLE_FAILURE",
      "reason":reason,"evidence":evidence}

def main():
    p=argparse.ArgumentParser()
    p.add_argument("--raw",required=True); p.add_argument("--out",required=True)
    p.add_argument("--os",required=True); p.add_argument("--version",required=True); p.add_argument("--arch",required=True)
    p.add_argument("--parent-label",default="ubuntu-24.04"); p.add_argument("--adapter-commit",required=True)
    a=p.parse_args(); v=parse(a.raw); commands={k[4:].replace("_","-"):x=="1" for k,x in v.items() if k.startswith("CMD_")}
    cpu=intval(v.get("CPU_ONLINE")); mem=intval(v.get("MEM_BYTES")); total=intval(v.get("ROOT_TOTAL_KIB")) or 0; free=intval(v.get("ROOT_FREE_KIB")) or 0
    identity=bool(v.get("UNAME_S") and v.get("UNAME_M"))
    receipt={
      "schema":"github-runner-capability/v1",
      "provenance":{"requested_label":f"qemu-guest:{a.os}:{a.version}:{a.arch}","repository_visibility":os.environ.get("CENSUS_REPOSITORY_VISIBILITY","public"),
        "workflow_sha":os.environ.get("GITHUB_SHA",""),"run_id":os.environ.get("GITHUB_RUN_ID",""),"run_attempt":os.environ.get("GITHUB_RUN_ATTEMPT",""),
        "probe_version":"public-qemu-guest/1","timestamp_utc":dt.datetime.now(dt.timezone.utc).isoformat().replace("+00:00","Z"),
        "image_os":a.os,"image_version":a.version,"guest_adapter":{"repository":"cross-platform-actions/action","commit":a.adapter_commit}},
      "runner":{"system":v.get("UNAME_S",""),"release":v.get("UNAME_R",""),"machine":v.get("UNAME_M",""),"architecture":a.arch,
        "runner_os":v.get("UNAME_S"),"runner_arch":v.get("UNAME_M"),"privileged":v.get("UID")=="0"},
      "resources":{"cpu":{"logical_processors":cpu,"model":None},"memory":{"total_bytes":mem,"available_bytes":None},
        "storage":[{"mount":"/","filesystem":v.get("ROOT_FS"),"total_bytes":total*1024,"free_bytes":free*1024}]},
      "environment":{"github_actions":True,"execution_model":"qemu-guest","parent_runner_label":a.parent_label,
        "requested_guest_os":a.os,"requested_guest_version":a.version,"requested_guest_arch":a.arch,
        "adapter_repository":"cross-platform-actions/action","adapter_commit":a.adapter_commit,"commands":commands,
        "uid":intval(v.get("UID")),"gid":intval(v.get("GID")),"case_insensitive":v.get("FS_CASE_INSENSITIVE")=="1"},
      "capabilities":[capability("guest:identity",identity,"guest uname identity observed",{"uname_s":v.get("UNAME_S"),"uname_r":v.get("UNAME_R"),"uname_m":v.get("UNAME_M")}),
        capability("filesystem:symlink",v.get("FS_SYMLINK")=="1","guest temp symlink read oracle"),
        capability("filesystem:hardlink",v.get("FS_HARDLINK")=="1","guest temp hardlink read oracle")],
      "observations":[{"name":"guest:command-surface","value":commands,"unit":None,"note":"presence only; no package installation"}],
      "warnings":["VM/QEMU guest portability evidence; not a native GitHub runner label","parent GitHub-hosted runner is distinct",
        "guest image digest is not surfaced by this adapter receipt; immutable image identity remains INCONCLUSIVE",
        "third-party adapter is pinned to an exact commit","no package installation or stress workload performed"],
    }
    path=pathlib.Path(a.out); path.parent.mkdir(parents=True,exist_ok=True); path.write_text(json.dumps(receipt,indent=2,sort_keys=True)+"\n")
    print(f"GUEST_RECEIPT={path}"); print(json.dumps(receipt,indent=2,sort_keys=True))
if __name__=="__main__": main()
