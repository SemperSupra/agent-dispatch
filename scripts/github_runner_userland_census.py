#!/usr/bin/env python3
from __future__ import annotations
import argparse, datetime as dt, json, os, pathlib, subprocess
from typing import Any

SCHEMA="github-runner-capability/v1"
PROBE_VERSION="public-docker-userland/1"

def run(argv:list[str], timeout:int=300):
    cp=subprocess.run(argv,check=False,capture_output=True,text=True,timeout=timeout)
    return cp.returncode,cp.stdout.strip(),cp.stderr.strip()

def cap(name:str, classification:str, reason:str, **kw)->dict[str,Any]:
    return {
        "name":name,"advertised":None,
        "observed":kw.get("observed"),"installed":kw.get("installed"),
        "callable":kw.get("callable_"),"exercised":kw.get("exercised",False),
        "oracleSatisfied":kw.get("oracle",False),"classification":classification,
        "reason":reason,"evidence":kw.get("evidence"),
    }

PROBE=r'''
set -eu
emit_file() {
  key="$1"; path="$2"
  if [ -r "$path" ]; then
    printf '%s_BEGIN\n' "$key"; cat "$path"; printf '\n%s_END\n' "$key"
  fi
}
printf 'UNAME_M=%s\n' "$(uname -m 2>/dev/null || true)"
printf 'UNAME_R=%s\n' "$(uname -r 2>/dev/null || true)"
printf 'UID=%s\n' "$(id -u 2>/dev/null || true)"
printf 'GID=%s\n' "$(id -g 2>/dev/null || true)"
emit_file OS_RELEASE /etc/os-release
for cmd in apt-get apt apk dnf microdnf yum rpm dpkg bash sh gcc clang cc make cmake python3 python node java go rustc; do
  if command -v "$cmd" >/dev/null 2>&1; then printf 'CMD_%s=1\n' "$cmd"; else printf 'CMD_%s=0\n' "$cmd"; fi
done
printf 'LIBC_BEGIN\n'
if command -v getconf >/dev/null 2>&1; then getconf GNU_LIBC_VERSION 2>/dev/null || true; fi
if command -v ldd >/dev/null 2>&1; then ldd --version 2>&1 | head -4 || true; fi
printf 'LIBC_END\n'
cpu=""
if command -v getconf >/dev/null 2>&1; then cpu="$(getconf _NPROCESSORS_ONLN 2>/dev/null || true)"; fi
if [ -z "$cpu" ] && command -v nproc >/dev/null 2>&1; then cpu="$(nproc 2>/dev/null || true)"; fi
printf 'CPU_ONLINE=%s\n' "$cpu"
for key in MemTotal MemAvailable SwapTotal SwapFree; do
  value="$(awk -v k="$key" '$1 == k ":" {print $2}' /proc/meminfo 2>/dev/null || true)"
  printf 'MEM_%s_KIB=%s\n' "$key" "$value"
done
df -Pk / 2>/dev/null | awk 'NR==2 {printf "ROOT_FS=%s\nROOT_TOTAL_KIB=%s\nROOT_FREE_KIB=%s\n",$1,$2,$4}' || true
tmp=/tmp/runner-userland-$$
mkdir -p "$tmp"; trap 'rm -rf "$tmp"' EXIT
printf nonce >"$tmp/CaseProbe"
if [ -e "$tmp/caseprobe" ]; then printf 'FS_CASE_INSENSITIVE=1\n'; else printf 'FS_CASE_INSENSITIVE=0\n'; fi
if ln -s "$tmp/CaseProbe" "$tmp/symlink" 2>/dev/null && [ "$(cat "$tmp/symlink")" = nonce ]; then printf 'FS_SYMLINK=1\n'; else printf 'FS_SYMLINK=0\n'; fi
if ln "$tmp/CaseProbe" "$tmp/hardlink" 2>/dev/null && [ "$(cat "$tmp/hardlink")" = nonce ]; then printf 'FS_HARDLINK=1\n'; else printf 'FS_HARDLINK=0\n'; fi
'''

def parse_sections(text:str):
    values={}; sections={}; active=None; buf=[]
    for line in text.splitlines():
        if line.endswith("_BEGIN") and "=" not in line:
            active=line[:-6]; buf=[]; continue
        if active and line==f"{active}_END":
            sections[active]="\n".join(buf).strip(); active=None; buf=[]; continue
        if active: buf.append(line); continue
        if "=" in line:
            k,v=line.split("=",1); values[k]=v
    return values,sections

def parse_os_release(raw:str):
    out={}
    for line in raw.splitlines():
        if "=" not in line: continue
        k,v=line.split("=",1)
        if k in {"ID","VERSION_ID","VERSION_CODENAME","PRETTY_NAME"}:
            out[k]=v.strip().strip('"')
    return out

def intval(v):
    try: return int(v) if v else None
    except (ValueError,TypeError): return None

def detect_libc(raw:str):
    low=raw.lower(); family=None
    if "musl" in low: family="musl"
    elif "glibc" in low or "gnu libc" in low: family="glibc"
    line=next((x.strip() for x in raw.splitlines() if x.strip()),None)
    return {"family":family,"evidence_line":line}

def main()->int:
    p=argparse.ArgumentParser()
    p.add_argument("--image",required=True); p.add_argument("--parent-label",default="ubuntu-24.04"); p.add_argument("--out",required=True)
    a=p.parse_args()

    code,_,err=run(["docker","pull",a.image])
    if code: raise SystemExit(f"pull failed: {err[-1500:]}")
    code,out,err=run(["docker","image","inspect",a.image,"--format",
        '{"repo_digests":{{json .RepoDigests}},"architecture":{{json .Architecture}},"os":{{json .Os}},"size":{{json .Size}}}'])
    if code: raise SystemExit(f"inspect failed: {err}")
    meta=json.loads(out); digests=meta.get("repo_digests") or []

    code,out,err=run(["docker","run","--rm","--network=none",a.image,"sh","-c",PROBE],120)
    if code: raise SystemExit(f"probe failed rc={code}: {err[-1500:]}")
    vals,sections=parse_sections(out); osrel=parse_os_release(sections.get("OS_RELEASE","")); libc=detect_libc(sections.get("LIBC",""))
    commands={k[4:].replace("_","-"):v=="1" for k,v in vals.items() if k.startswith("CMD_")}
    pms=[x for x in ("apt-get","apt","apk","dnf","microdnf","yum","rpm","dpkg") if commands.get(x)]
    cpu=intval(vals.get("CPU_ONLINE")); mt=intval(vals.get("MEM_MemTotal_KIB")); ma=intval(vals.get("MEM_MemAvailable_KIB"))
    rt=intval(vals.get("ROOT_TOTAL_KIB")) or 0; rf=intval(vals.get("ROOT_FREE_KIB")) or 0

    caps=[
        cap("container:image-resolution","SUPPORTED" if digests else "ORACLE_FAILURE",
            "image resolved to repository digest" if digests else "no repository digest reported",
            observed=True,installed=True,callable_=True,exercised=True,oracle=bool(digests),
            evidence={"requested_image":a.image,"repo_digests":digests,"architecture":meta.get("architecture"),"size_bytes":meta.get("size")}),
        cap("userland:package-manager","INCONCLUSIVE" if pms else "NEGATIVE_OBSERVATION",
            "package manager observed; no install performed" if pms else "no selected package manager observed",
            observed=bool(pms),installed=bool(pms),evidence={"commands":pms}),
        cap("userland:libc-family","SUPPORTED" if libc["family"] else "INCONCLUSIVE",
            f"{libc['family']} identified" if libc["family"] else "libc family not identified",
            observed=bool(libc["family"]),exercised=True,oracle=bool(libc["family"]),evidence=libc),
        cap("filesystem:symlink","SUPPORTED" if vals.get("FS_SYMLINK")=="1" else "ORACLE_FAILURE",
            "experiment-owned symlink oracle",observed=vals.get("FS_SYMLINK")=="1",callable_=True,exercised=True,oracle=vals.get("FS_SYMLINK")=="1"),
        cap("filesystem:hardlink","SUPPORTED" if vals.get("FS_HARDLINK")=="1" else "ORACLE_FAILURE",
            "experiment-owned hardlink oracle",observed=vals.get("FS_HARDLINK")=="1",callable_=True,exercised=True,oracle=vals.get("FS_HARDLINK")=="1"),
    ]
    receipt={
      "schema":SCHEMA,
      "provenance":{
        "requested_label":f"docker-userland:{a.image}","repository_visibility":os.environ.get("CENSUS_REPOSITORY_VISIBILITY","public"),
        "workflow_sha":os.environ.get("GITHUB_SHA",""),"run_id":os.environ.get("GITHUB_RUN_ID",""),"run_attempt":os.environ.get("GITHUB_RUN_ATTEMPT",""),
        "probe_version":PROBE_VERSION,"timestamp_utc":dt.datetime.now(dt.timezone.utc).isoformat().replace("+00:00","Z"),
        "image_os":osrel.get("ID"),"image_version":osrel.get("VERSION_ID"),"resolved_container_digests":digests,
      },
      "runner":{"system":"Linux","release":osrel.get("VERSION_ID") or vals.get("UNAME_R",""),"machine":vals.get("UNAME_M",""),
        "architecture":meta.get("architecture") or vals.get("UNAME_M",""),"runner_os":"Linux","runner_arch":os.environ.get("RUNNER_ARCH"),
        "privileged":vals.get("UID")=="0"},
      "resources":{"cpu":{"logical_processors":cpu,"model":None},"memory":{"total_bytes":mt*1024 if mt is not None else None,
        "available_bytes":ma*1024 if ma is not None else None},
        "storage":[{"mount":"/","filesystem":vals.get("ROOT_FS"),"total_bytes":rt*1024,"free_bytes":rf*1024}]},
      "environment":{"github_actions":os.environ.get("GITHUB_ACTIONS")=="true","execution_model":"docker-container-userland",
        "parent_runner_label":a.parent_label,"container_image_requested":a.image,"container_repo_digests":digests,
        "host_kernel_shared":True,"network_mode":"none","uid":intval(vals.get("UID")),"gid":intval(vals.get("GID")),
        "os_release":osrel,"libc":libc,"case_insensitive":vals.get("FS_CASE_INSENSITIVE")=="1","commands":commands},
      "capabilities":caps,
      "observations":[{"name":"userland:identity","value":{"requested_image":a.image,"resolved_digests":digests,"os_release":osrel,
        "architecture":meta.get("architecture"),"image_size_bytes":meta.get("size"),"libc":libc,"package_managers":pms},"unit":None,
        "note":"userland identity only; parent host kernel is shared"}],
      "warnings":["Docker userland receipt is not native GitHub runner OS evidence","parent host kernel is shared",
        "requested tag is bound to resolved repository digest","no packages installed; probe runs with network disabled",
        "container-visible resources are observations, not guarantees"],
    }
    path=pathlib.Path(a.out); path.parent.mkdir(parents=True,exist_ok=True); path.write_text(json.dumps(receipt,indent=2,sort_keys=True)+"\n")
    print(f"USERLAND_RECEIPT={path}"); print(json.dumps(receipt,indent=2,sort_keys=True)); return 0

if __name__=="__main__": raise SystemExit(main())
