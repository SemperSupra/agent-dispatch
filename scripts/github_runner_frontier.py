#!/usr/bin/env python3
"""Targeted frontier oracles for GitHub-hosted runner capability discovery."""
from __future__ import annotations

import argparse
import json
import os
import pathlib
import platform
import re
import shutil
import subprocess
import sys
import tempfile
import time
import uuid

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
import github_runner_census as passive

PROBE_VERSION = "public-frontier/1"
NONCE = 0xC0DEF00D

def _run(argv: list[str], timeout: int = 15) -> tuple[int | None, str, str]:
    try:
        cp = subprocess.run(argv, check=False, capture_output=True, text=True, timeout=timeout)
        return cp.returncode, cp.stdout.strip(), cp.stderr.strip()
    except subprocess.TimeoutExpired:
        return None, "", f"timeout after {timeout}s"
    except (OSError, subprocess.SubprocessError) as exc:
        return None, "", str(exc)

def _cap(name: str, *, observed, installed, callable_, exercised, oracle,
         classification: str, reason: str, evidence=None) -> dict:
    return {
        "name": name, "advertised": None, "observed": observed, "installed": installed,
        "callable": callable_, "exercised": exercised, "oracleSatisfied": oracle,
        "classification": classification, "reason": reason, "evidence": evidence,
    }

KVM_NONCE_SOURCE = r"""
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <linux/kvm.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <unistd.h>
#define GUEST_ADDR 0x1000
#define MEM_SIZE 0x1000
#define NONCE 0xC0DEF00Du
static int die(const char *w) { fprintf(stderr,"%s: %s\n",w,strerror(errno)); return 2; }
int main(void) {
    int kvm=-1, vm=-1, vcpu=-1, rc=2, mmap_size=0;
    void *mem=MAP_FAILED; struct kvm_run *run=MAP_FAILED;
    kvm=open("/dev/kvm",O_RDWR|O_CLOEXEC); if(kvm<0) return die("open /dev/kvm");
    int api=ioctl(kvm,KVM_GET_API_VERSION,0); if(api!=12){fprintf(stderr,"api=%d\n",api);goto out;}
    vm=ioctl(kvm,KVM_CREATE_VM,0); if(vm<0){die("KVM_CREATE_VM");goto out;}
    mem=mmap(NULL,MEM_SIZE,PROT_READ|PROT_WRITE,MAP_PRIVATE|MAP_ANONYMOUS,-1,0);
    if(mem==MAP_FAILED){die("mmap guest");goto out;}
    const uint8_t code[]={0x66,0xB8,0x0D,0xF0,0xDE,0xC0,0xF4};
    memcpy(mem,code,sizeof(code));
    struct kvm_userspace_memory_region region={.slot=0,.guest_phys_addr=GUEST_ADDR,
        .memory_size=MEM_SIZE,.userspace_addr=(uint64_t)(uintptr_t)mem};
    if(ioctl(vm,KVM_SET_USER_MEMORY_REGION,&region)<0){die("KVM_SET_USER_MEMORY_REGION");goto out;}
    vcpu=ioctl(vm,KVM_CREATE_VCPU,0); if(vcpu<0){die("KVM_CREATE_VCPU");goto out;}
    mmap_size=ioctl(kvm,KVM_GET_VCPU_MMAP_SIZE,0);
    if(mmap_size<(int)sizeof(*run)){fprintf(stderr,"mmap_size=%d\n",mmap_size);goto out;}
    run=mmap(NULL,(size_t)mmap_size,PROT_READ|PROT_WRITE,MAP_SHARED,vcpu,0);
    if(run==MAP_FAILED){die("mmap kvm_run");goto out;}
    struct kvm_sregs sregs; if(ioctl(vcpu,KVM_GET_SREGS,&sregs)<0){die("KVM_GET_SREGS");goto out;}
    sregs.cs.base=0; sregs.cs.selector=0;
    if(ioctl(vcpu,KVM_SET_SREGS,&sregs)<0){die("KVM_SET_SREGS");goto out;}
    struct kvm_regs regs={.rip=GUEST_ADDR,.rflags=2};
    if(ioctl(vcpu,KVM_SET_REGS,&regs)<0){die("KVM_SET_REGS");goto out;}
    if(ioctl(vcpu,KVM_RUN,0)<0){die("KVM_RUN");goto out;}
    if(ioctl(vcpu,KVM_GET_REGS,&regs)<0){die("KVM_GET_REGS");goto out;}
    uint32_t got=(uint32_t)(regs.rax&0xffffffffu);
    printf("KVM_NONCE=%08x EXIT=%u API=%d\n",got,run->exit_reason,api);
    rc=(run->exit_reason==KVM_EXIT_HLT && got==NONCE)?0:3;
out:
    if(run!=MAP_FAILED && mmap_size>0) munmap(run,(size_t)mmap_size);
    if(vcpu>=0) close(vcpu); if(mem!=MAP_FAILED) munmap(mem,MEM_SIZE);
    if(vm>=0) close(vm); if(kvm>=0) close(kvm); return rc;
}
"""

def probe_kvm_vcpu_nonce() -> list[dict]:
    if platform.system() != "Linux" or platform.machine() not in {"x86_64","amd64"}:
        return [_cap("linux:kvm-vcpu-nonce", observed=False, installed=False, callable_=False,
            exercised=False, oracle=False, classification="SKIPPED_GUARDRAIL",
            reason="minimal VCPU nonce probe is x86_64 Linux-only")]
    if not pathlib.Path("/dev/kvm").exists():
        return [_cap("linux:kvm-vcpu-nonce", observed=False, installed=False, callable_=False,
            exercised=False, oracle=False, classification="NEGATIVE_OBSERVATION",
            reason="/dev/kvm not present")]
    sudo=shutil.which("sudo"); cc=shutil.which("cc") or shutil.which("gcc")
    header=pathlib.Path("/usr/include/linux/kvm.h")
    if not sudo or not cc or not header.exists():
        return [_cap("linux:kvm-vcpu-nonce", observed=True, installed=False, callable_=False,
            exercised=False, oracle=False, classification="SKIPPED_GUARDRAIL",
            reason="existing sudo/compiler/KVM headers do not satisfy entry gate",
            evidence={"sudo":bool(sudo),"compiler":cc,"kvm_header":header.exists()})]
    with tempfile.TemporaryDirectory(prefix="runner-kvm-frontier-") as td:
        root=pathlib.Path(td); src=root/"kvm_nonce.c"; binary=root/"kvm_nonce"
        src.write_text(KVM_NONCE_SOURCE,encoding="utf-8")
        code,_,err=_run([cc,"-O2","-Wall","-Wextra","-std=c11",str(src),"-o",str(binary)],30)
        if code != 0:
            return [_cap("linux:kvm-vcpu-nonce", observed=True, installed=True, callable_=None,
                exercised=False, oracle=False, classification="HARNESS_FAILURE",
                reason="minimal KVM oracle failed to compile",
                evidence={"compiler":cc,"exit_code":code,"stderr":err[:1500] if err else None})]
        run_code,out,run_err=_run([sudo,"-n",str(binary)],20)
    m=re.search(r"KVM_NONCE=([0-9a-fA-F]{8})\s+EXIT=(\d+)\s+API=(\d+)",out)
    got=int(m.group(1),16) if m else None; exit_reason=int(m.group(2)) if m else None
    api=int(m.group(3)) if m else None
    ok=run_code==0 and got==NONCE and exit_reason==5 and api==12
    return [_cap("linux:kvm-vcpu-nonce", observed=True, installed=True, callable_=run_code is not None,
        exercised=True, oracle=ok, classification="SUPPORTED" if ok else "ORACLE_FAILURE",
        reason="minimal KVM VCPU executed register nonce and exited HLT" if ok else "minimal KVM VCPU nonce oracle failed",
        evidence={"exit_code":run_code,"nonce":f"{got:08x}" if got is not None else None,
                  "kvm_exit_reason":exit_reason,"api_version":api,
                  "stdout":out[:1000] if out else None,"stderr":run_err[:1500] if run_err else None})]

def _latest_ios_and_iphone(xcrun: str):
    rc,rout,rerr=_run([xcrun,"simctl","list","runtimes","-j"],20)
    dc,dout,derr=_run([xcrun,"simctl","list","devicetypes","-j"],20)
    ev={"runtime_exit":rc,"device_type_exit":dc,
        "stderr":"\n".join(x for x in (rerr,derr) if x)[:1200] or None}
    if rc!=0 or dc!=0: return None,None,ev
    try:
        runtimes=json.loads(rout).get("runtimes",[]); devtypes=json.loads(dout).get("devicetypes",[])
    except json.JSONDecodeError as exc:
        ev["json_error"]=str(exc); return None,None,ev
    ios=[r for r in runtimes if r.get("isAvailable") and
         str(r.get("identifier","")).startswith("com.apple.CoreSimulator.SimRuntime.iOS-")]
    iphones=[d for d in devtypes if str(d.get("identifier","")).startswith("com.apple.CoreSimulator.SimDeviceType.iPhone-")]
    def key(r): return tuple(int(x) for x in re.findall(r"\d+",str(r.get("version","0"))))
    return (sorted(ios,key=key)[-1] if ios else None,
            sorted(iphones,key=lambda d:str(d.get("identifier","")))[-1] if iphones else None,ev)

def _device_state(xcrun: str, udid: str):
    code,out,err=_run([xcrun,"simctl","list","devices","-j"],15)
    if code!=0 or not out: return None,err or f"list devices exit={code}"
    try: payload=json.loads(out)
    except json.JSONDecodeError as exc: return None,str(exc)
    for devices in payload.get("devices",{}).values():
        for dev in devices:
            if dev.get("udid")==udid: return dev.get("state"),None
    return None,"UDID not present in simctl list devices"

def probe_simulator_state() -> list[dict]:
    names=("macos:simulator-device-boot","macos:simulator-service-query","macos:simulator-guest-spawn")
    if platform.system()!="Darwin":
        return [_cap(n,observed=False,installed=False,callable_=False,exercised=False,oracle=False,
            classification="SKIPPED_GUARDRAIL",reason="Simulator probe is macOS-only") for n in names]
    xcrun=shutil.which("xcrun")
    if not xcrun:
        return [_cap(n,observed=False,installed=False,callable_=False,exercised=False,oracle=False,
            classification="NEGATIVE_OBSERVATION",reason="xcrun not present") for n in names]
    runtime,devtype,entry=_latest_ios_and_iphone(xcrun)
    if not runtime or not devtype:
        return [_cap(n,observed=True,installed=True,callable_=False,exercised=False,oracle=False,
            classification="SKIPPED_GUARDRAIL",reason="available iOS runtime/device-type entry gate not satisfied",
            evidence=entry) for n in names]
    name="RunnerFrontier-"+uuid.uuid4().hex[:8]
    create_code,udid,create_err=_run([xcrun,"simctl","create",name,devtype["identifier"],runtime["identifier"]],30)
    udid=udid.strip()
    common={"runtime":runtime.get("identifier"),"runtime_version":runtime.get("version"),
            "device_type":devtype.get("identifier"),"create_exit":create_code,
            "create_stderr":create_err[:800] if create_err else None}
    if create_code!=0 or not udid:
        return [_cap(names[0],observed=True,installed=True,callable_=True,exercised=True,oracle=False,
            classification="ORACLE_FAILURE",reason="disposable Simulator device creation failed",evidence=common),
            *[_cap(n,observed=True,installed=True,callable_=True,exercised=False,oracle=False,
                classification="SKIPPED_GUARDRAIL",reason="device creation gate failed",evidence=common) for n in names[1:]]]
    boot_code=None; final_state=None; state_error=None; polls=0
    service_code=spawn_code=None; service_out=spawn_out=service_err=spawn_err=""
    try:
        boot_code,_,boot_err=_run([xcrun,"simctl","boot",udid],30)
        deadline=time.monotonic()+90
        while boot_code==0 and time.monotonic()<deadline:
            polls+=1; final_state,state_error=_device_state(xcrun,udid)
            if final_state=="Booted": break
            time.sleep(2)
        boot_ok=boot_code==0 and final_state=="Booted"
        if boot_ok:
            service_code,service_out,service_err=_run([xcrun,"simctl","getenv",udid,"HOME"],15)
            spawn_code,spawn_out,spawn_err=_run([xcrun,"simctl","spawn",udid,"/usr/bin/true"],15)
        service_ok=boot_ok and service_code==0 and bool(service_out.strip())
        spawn_ok=boot_ok and spawn_code==0
    finally:
        _run([xcrun,"simctl","shutdown",udid],20); _run([xcrun,"simctl","delete",udid],20)
    bev={**common,"boot_exit":boot_code,"final_state":final_state,"state_polls":polls,
         "state_error":state_error,"boot_stderr":boot_err[:800] if boot_err else None}
    sev={**bev,"service_exit":service_code,"service_value_nonempty":bool(service_out.strip()),
         "service_stderr":service_err[:800] if service_err else None}
    pev={**bev,"spawn_exit":spawn_code,"spawn_stdout":spawn_out[:300] if spawn_out else None,
         "spawn_stderr":spawn_err[:800] if spawn_err else None}
    boot_cap=_cap(names[0],observed=True,installed=True,callable_=True,exercised=True,oracle=boot_ok,
        classification="SUPPORTED" if boot_ok else "ORACLE_FAILURE",
        reason="disposable Simulator reached Booted state" if boot_ok else "Simulator did not reach Booted state within bounded poll window",
        evidence=bev)
    if not boot_ok:
        return [boot_cap,
            _cap(names[1],observed=True,installed=True,callable_=True,exercised=False,oracle=False,
                classification="SKIPPED_GUARDRAIL",reason="device boot-state gate failed",evidence=sev),
            _cap(names[2],observed=True,installed=True,callable_=True,exercised=False,oracle=False,
                classification="SKIPPED_GUARDRAIL",reason="device boot-state gate failed",evidence=pev)]
    return [boot_cap,
        _cap(names[1],observed=True,installed=True,callable_=True,exercised=True,oracle=service_ok,
            classification="SUPPORTED" if service_ok else "ORACLE_FAILURE",
            reason="simctl getenv returned guest environment value" if service_ok else "simctl guest environment query failed",evidence=sev),
        _cap(names[2],observed=True,installed=True,callable_=True,exercised=True,oracle=spawn_ok,
            classification="SUPPORTED" if spawn_ok else "ORACLE_FAILURE",
            reason="simctl spawned /usr/bin/true in booted Simulator" if spawn_ok else "simctl guest process launch failed",evidence=pev)]

PROBES={"kvm-vcpu-nonce":probe_kvm_vcpu_nonce,"simulator-state":probe_simulator_state}

def build_receipt(probe: str,label: str|None=None)->dict:
    receipt=passive.build_receipt(label); receipt["provenance"]["probe_version"]=f"{PROBE_VERSION}:{probe}"
    receipt["capabilities"].extend(PROBES[probe]())
    receipt["warnings"].append("frontier result proves only the named oracle rung; it does not imply representative workload qualification")
    return receipt

def main()->int:
    p=argparse.ArgumentParser(); p.add_argument("--probe",choices=sorted(PROBES),required=True)
    p.add_argument("--label"); p.add_argument("--out",required=True); a=p.parse_args()
    r=build_receipt(a.probe,a.label); path=pathlib.Path(a.out); path.parent.mkdir(parents=True,exist_ok=True)
    path.write_text(json.dumps(r,indent=2,sort_keys=True)+"\n",encoding="utf-8")
    print(f"FRONTIER_RECEIPT={path}"); print(json.dumps(r,indent=2,sort_keys=True)); return 0
if __name__=="__main__": raise SystemExit(main())
