#!/usr/bin/env python3
"""R2: bounded outbound-only Firecracker network envelope on GHA x86_64."""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import pathlib
import platform
import re
import shutil
import stat
import subprocess
import sys
import tempfile
import time

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
import github_runner_firecracker_f0 as f0
import github_runner_firecracker_f1_boot as f1
import github_runner_firecracker_f3_useful_work as f3
from firecracker_lifecycle_timing import LifecycleTimer

SCHEMA="firecracker-r2-network-envelope/v1"
AUTHORITY="SemperSupra/agent-dispatch-private#287"
PROBE_SOURCE=pathlib.Path("experiments/firecracker/guest/r2-network-probe.go")
CA_BUNDLE=pathlib.Path("/etc/ssl/certs/ca-certificates.crt")
GUEST_IP="192.0.2.2"
TAP_IP="192.0.2.1"
CIDR="30"
DNS_SERVER="1.1.1.1"
RESULT_RE=re.compile(
    r"FIRECRACKER_R2_NETWORK dns_ipv4=(\d+) https_status=(\d+) body_bytes=(\d+) "
    r"tls_version=(\d+) metadata_blocked=(true|false) host_blocked=(true|false) elapsed_ms=(\d+)"
)

def _sha256(path:pathlib.Path)->str:
    h=hashlib.sha256()
    with path.open("rb") as fh:
        for chunk in iter(lambda:fh.read(1024*1024),b""):
            h.update(chunk)
    return h.hexdigest()

def _compile_go(source:pathlib.Path,out:pathlib.Path)->dict:
    go=shutil.which("go")
    if not go:
        return {"ok":False,"reason":"go unavailable"}
    env=dict(os.environ)
    env.update({"CGO_ENABLED":"0","GOOS":"linux","GOARCH":"amd64"})
    cp=subprocess.run(
        [go,"build","-trimpath","-ldflags=-s -w -buildid=","-o",str(out),str(source)],
        capture_output=True,text=True,timeout=60,check=False,env=env,
    )
    return {"ok":cp.returncode==0 and out.exists(),"exit_code":cp.returncode,"stderr":cp.stderr[-3000:]}

def _build_initramfs(init_bin:pathlib.Path,candidate:pathlib.Path,ca:pathlib.Path,out:pathlib.Path)->None:
    payload=b"".join([
        f1._newc_entry(".",mode=stat.S_IFDIR|0o755,ino=1,nlink=2),
        f1._newc_entry("dev",mode=stat.S_IFDIR|0o755,ino=2,nlink=2),
        f1._newc_entry("dev/console",mode=stat.S_IFCHR|0o600,ino=3,rdevmajor=5,rdevminor=1),
        f1._newc_entry("work",mode=stat.S_IFDIR|0o555,ino=4,nlink=2),
        f1._newc_entry("work/candidate",mode=stat.S_IFREG|0o555,data=candidate.read_bytes(),ino=5),
        f1._newc_entry("etc",mode=stat.S_IFDIR|0o755,ino=6,nlink=2),
        f1._newc_entry("etc/ssl",mode=stat.S_IFDIR|0o755,ino=7,nlink=2),
        f1._newc_entry("etc/ssl/certs",mode=stat.S_IFDIR|0o755,ino=8,nlink=2),
        f1._newc_entry("etc/ssl/certs/ca-certificates.crt",mode=stat.S_IFREG|0o444,data=ca.read_bytes(),ino=9),
        f1._newc_entry("init",mode=stat.S_IFREG|0o755,data=init_bin.read_bytes(),ino=10),
        f1._newc_entry("TRAILER!!!",mode=0,ino=11),
    ])
    out.write_bytes(payload)

def _sudo(argv:list[str],timeout:int=20)->dict:
    sudo=shutil.which("sudo")
    if not sudo:
        return {"ok":False,"exit_code":None,"stdout":"","stderr":"sudo unavailable"}
    code,out,err=f0._run([sudo,"-n",*argv],timeout=timeout)
    return {"ok":code==0,"exit_code":code,"stdout":out or "","stderr":err or ""}

def _default_uplink()->str|None:
    ip=shutil.which("ip")
    if not ip:
        return None
    code,out,err=f0._run([ip,"route","show","default"],timeout=5)
    if code!=0:
        return None
    m=re.search(r"\bdev\s+(\S+)",out)
    return m.group(1) if m else None

def _iptables_bin()->str|None:
    return shutil.which("iptables-nft") or shutil.which("iptables")

def _network_preflight()->dict:
    return {
        "ip":shutil.which("ip"),
        "iptables":_iptables_bin(),
        "sudo":shutil.which("sudo"),
        "go":shutil.which("go"),
        "ca_bundle":CA_BUNDLE.exists(),
        "tun_present":pathlib.Path("/dev/net/tun").exists(),
        "uplink":_default_uplink(),
    }

def _ipt(binary:str,args:list[str],timeout:int=20)->dict:
    return _sudo([binary,*args],timeout=timeout)

def _setup_network(work:pathlib.Path,tap_owner_uid:int|None=None)->dict:
    pf=_network_preflight()
    if not all([pf["ip"],pf["iptables"],pf["sudo"],pf["tun_present"],pf["uplink"]]):
        raise RuntimeError(f"network preflight failed: {pf}")
    pid=os.getpid()
    tap=f"fcr2{pid}"[:15]
    chain=f"FCR2_{pid}"[:28]
    ipt=pf["iptables"]
    original_forward=pathlib.Path("/proc/sys/net/ipv4/ip_forward").read_text().strip()

    tap_create=["ip","tuntap","add","dev",tap,"mode","tap"]
    if tap_owner_uid is not None:
        tap_create += ["user",str(tap_owner_uid)]
    for argv in [
        tap_create,
        ["ip","addr","add",f"{TAP_IP}/{CIDR}","dev",tap],
        ["ip","link","set",tap,"up"],
        ["sysctl","-w","net.ipv4.ip_forward=1"],
    ]:
        rr=_sudo(argv)
        if not rr["ok"]:
            raise RuntimeError(f"network setup failed: {argv}: {rr['stderr']}")

    created=[]
    def apply(args:list[str]):
        rr=_ipt(ipt,args)
        if not rr["ok"]:
            raise RuntimeError(f"iptables setup failed: {args}: {rr['stderr']}")
        created.append(args)

    try:
        apply(["-N",chain])
        for cidr in [
            "0.0.0.0/8","10.0.0.0/8","100.64.0.0/10","127.0.0.0/8",
            "169.254.0.0/16","172.16.0.0/12","192.168.0.0/16",
            "224.0.0.0/4","240.0.0.0/4",
        ]:
            apply(["-A",chain,"-d",cidr,"-j","DROP"])
        apply(["-A",chain,"-o",pf["uplink"],"-j","ACCEPT"])
        apply(["-A",chain,"-j","DROP"])
        apply(["-I","FORWARD","1","-i",tap,"-j",chain])
        apply(["-I","FORWARD","1","-o",tap,"-m","conntrack","--ctstate","RELATED,ESTABLISHED","-j","ACCEPT"])
        apply(["-I","INPUT","1","-i",tap,"-j","DROP"])
        apply(["-t","nat","-A","POSTROUTING","-s",f"{GUEST_IP}/32","-o",pf["uplink"],"-j","MASQUERADE"])
    except Exception:
        _cleanup_network({
            "tap":tap,"chain":chain,"uplink":pf["uplink"],"iptables":ipt,
            "original_ip_forward":original_forward,
        })
        raise

    return {
        "tap":tap,"chain":chain,"uplink":pf["uplink"],"iptables":ipt,
        "tap_owner_uid":tap_owner_uid,
        "original_ip_forward":original_forward,"preflight":pf,
    }

def _network_ruleset(state:dict)->str:
    ipt=state["iptables"]
    parts=[]
    for args in [
        ["-L",state["chain"],"-v","-n","-x"],
        ["-t","nat","-L","POSTROUTING","-v","-n","-x"],
        ["-L","INPUT","-v","-n","-x"],
    ]:
        rr=_ipt(ipt,args)
        parts.append(rr["stdout"] if rr["ok"] else rr["stderr"])
    return "\n---\n".join(parts)

def _cleanup_network(state:dict|None)->dict:
    if not state:
        return {"ok":True}
    ipt=state.get("iptables") or _iptables_bin()
    actions=[]
    commands=[
        [ipt,"-t","nat","-D","POSTROUTING","-s",f"{GUEST_IP}/32","-o",state["uplink"],"-j","MASQUERADE"],
        [ipt,"-D","INPUT","-i",state["tap"],"-j","DROP"],
        [ipt,"-D","FORWARD","-o",state["tap"],"-m","conntrack","--ctstate","RELATED,ESTABLISHED","-j","ACCEPT"],
        [ipt,"-D","FORWARD","-i",state["tap"],"-j",state["chain"]],
        [ipt,"-F",state["chain"]],
        [ipt,"-X",state["chain"]],
        ["ip","link","del",state["tap"]],
        ["sysctl","-w",f"net.ipv4.ip_forward={state['original_ip_forward']}"],
    ]
    for argv in commands:
        if not argv[0]:
            continue
        actions.append({"argv":argv,**_sudo(argv)})
    # Missing rules during partial-setup cleanup are tolerated; link/sysctl restoration must succeed.
    essential=[a for a in actions if a["argv"][0] in {"ip","sysctl"}]
    return {"ok":all(a["ok"] for a in essential),"actions":actions}

def _counter_for(ruleset:str,needle:str)->int:
    total=0
    for line in ruleset.splitlines():
        if needle not in line:
            continue
        # iptables-nft verbose list: packets is the first numeric column.
        m=re.match(r"\s*(\d+)\s+",line)
        if m:
            total+=int(m.group(1))
            continue
        # Retain compatibility with earlier native-nft receipt text.
        m=re.search(r"counter packets (\d+)",line)
        if m:
            total+=int(m.group(1))
    return total

def run_probe(label:str)->dict:
    timer=LifecycleTimer()
    if platform.system()!="Linux" or platform.machine() not in {"x86_64","amd64"}:
        return {"schema":SCHEMA,"authority":AUTHORITY,"result":{"classification":"SETUP_REQUIRED"}}
    if not CA_BUNDLE.exists():
        return {"schema":SCHEMA,"authority":AUTHORITY,"result":{"classification":"SETUP_REQUIRED","reason":"host CA bundle unavailable"}}

    vm=f1._load_json(f3.VMM_MANIFEST); km=f1._load_json(f3.KERNEL_MANIFEST)
    state=None
    cleanup=None
    with tempfile.TemporaryDirectory(prefix="firecracker-r2-") as td:
        w=pathlib.Path(td); archive=w/"firecracker.tgz"; extract=w/"vmm"; extract.mkdir()
        kernel=w/"vmlinux"; init_bin=w/"init"; candidate=w/"netprobe"; initrd=w/"initrd.cpio"; config_path=w/"vm.json"

        with timer.stage("vmm_download_and_verify","venue"):
            vv=f1._download_and_verify(vm["archive_url"],vm["archive_sha256"],archive)
        with timer.stage("vmm_extract","portable"):
            f0._safe_extract(archive,extract); fc=f1._find_firecracker(extract,vm["version"],vm["architecture"])
        with timer.stage("kernel_download_and_verify","venue"):
            kv=f1._download_and_verify(km["kernel_url"],km["kernel_sha256"],kernel)
        with timer.stage("guest_init_compile","portable"):
            ic=f1._compile_init(f3.INIT_SOURCE,init_bin)
        with timer.stage("network_probe_compile","portable"):
            nc=_compile_go(PROBE_SOURCE,candidate)
        if not all([vv["verified"],kv["verified"],ic["ok"],nc["ok"]]):
            return {"schema":SCHEMA,"authority":AUTHORITY,"result":{"classification":"HARNESS_FAILURE"}}
        with timer.stage("initramfs_build","portable"):
            _build_initramfs(init_bin,candidate,CA_BUNDLE,initrd)
        try:
            with timer.stage("host_network_setup","venue"):
                state=_setup_network(w)
            cfg=f1._build_config(kernel,initrd,config_path)
            cfg["machine-config"]["mem_size_mib"]=256
            cfg["boot-source"]["boot_args"] += f" ip={GUEST_IP}::{TAP_IP}:255.255.255.252::eth0:off"
            cfg["network-interfaces"]=[{
                "iface_id":"r2net0",
                "guest_mac":"06:00:00:00:02:02",
                "host_dev_name":state["tap"],
            }]
            config_path.write_text(json.dumps(cfg,indent=2,sort_keys=True)+"\n")

            with timer.stage("network_guest_lifecycle","portable"):
                execution=f3.run_vm(fc,config_path,{"bytes":0,"lines":0,"words":0,"fnv1a64":""},timeout_seconds=20)
            ruleset=_network_ruleset(state)
        finally:
            with timer.stage("host_network_cleanup","venue"):
                cleanup=_cleanup_network(state)

        output=execution.get("output_tail","")
        m=RESULT_RE.search(output)
        observed=None
        if m:
            observed={
                "dns_ipv4":int(m.group(1)),
                "https_status":int(m.group(2)),
                "body_bytes":int(m.group(3)),
                "tls_version":int(m.group(4)),
                "metadata_blocked":m.group(5)=="true",
                "host_blocked":m.group(6)=="true",
                "elapsed_ms":int(m.group(7)),
            }
        metadata_counter=_counter_for(ruleset,"169.254.0.0/16")
        nat_counter=_counter_for(ruleset,"MASQUERADE")
        oracle=bool(observed) and (
            observed["dns_ipv4"]>0
            and 200<=observed["https_status"]<400
            and observed["body_bytes"]>0
            and observed["tls_version"]>=771
            and observed["metadata_blocked"]
            and observed["host_blocked"]
            and metadata_counter>=1
            and nat_counter>=1
            and execution.get("clean_vmm_exit_observed")
            and cleanup and cleanup["ok"]
        )
        return {
            "schema":SCHEMA,"authority":AUTHORITY,"requested_label":label,
            "result":{
                "classification":"SUPPORTED" if oracle else "ORACLE_FAILURE",
                "outbound_dns_https_supported":oracle,
            },
            "guest":observed,
            "policy_evidence":{
                "metadata_drop_packets":metadata_counter,
                "nat_packets":nat_counter,
                "ruleset":ruleset[-8000:],
            },
            "host_network":{
                "state":state,
                "cleanup":cleanup,
                "ca_bundle_sha256":_sha256(CA_BUNDLE),
            },
            "execution_output_tail":output[-7000:],
            "lifecycle_timing":timer.receipt(),
            "next_gate":"Compose R2 with jailer, then R3 credential-minimized API-driven agent/model feasibility if earned.",
        }

def main()->int:
    p=argparse.ArgumentParser(); p.add_argument("--label",required=True); p.add_argument("--out",type=pathlib.Path,required=True)
    a=p.parse_args(); a.out.parent.mkdir(parents=True,exist_ok=True)
    try: receipt=run_probe(a.label)
    except Exception as exc:
        receipt={"schema":SCHEMA,"authority":AUTHORITY,"result":{"classification":"HARNESS_FAILURE","reason":f"{type(exc).__name__}: {exc}"}}
    a.out.write_text(json.dumps(receipt,indent=2,sort_keys=True)+"\n"); print(json.dumps(receipt,indent=2,sort_keys=True))
    return 0 if receipt["result"]["classification"]=="SUPPORTED" else 1

if __name__=="__main__": raise SystemExit(main())
