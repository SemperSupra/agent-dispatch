#!/usr/bin/env python3
"""R3b-0: jailed guest -> one-use host inference-broker seam with deterministic backend."""
from __future__ import annotations

import argparse
import hashlib
import http.server
import json
import os
import pathlib
import platform
import re
import secrets
import shutil
import socketserver
import subprocess
import sys
import tempfile
import threading
import time

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))

import github_runner_firecracker_f0 as f0
import github_runner_firecracker_f1_boot as f1
import github_runner_firecracker_f3_useful_work as f3
import github_runner_firecracker_j1_jailed_f3 as j1
import github_runner_firecracker_r2_network as r2
import github_runner_firecracker_u1_userspace as u1
import github_runner_firecracker_u2_composed as u2
from firecracker_lifecycle_timing import LifecycleTimer

SCHEMA="firecracker-r3b0-inference-broker/v1"
AUTHORITY="SemperSupra/agent-dispatch-private#287"
USERSPACE_MANIFEST=pathlib.Path("experiments/firecracker/guest-userspace-ubuntu-24.04-x86_64.json")
INIT_SOURCE=pathlib.Path("experiments/firecracker/guest/r3b-bridge-init-x86_64.c")
GUEST_SOURCE=pathlib.Path("experiments/firecracker/guest/r3b-broker-probe.py")
BROKER_PORT=38080
RESULT_RE=re.compile(
    r"FIRECRACKER_R3B_BROKER first=(\d+) second=(\d+) "
    r"request_sha256=([0-9a-f]{64}) response_sha256=([0-9a-f]{64}) "
    r"other_host_blocked=(\d+) metadata_blocked=(\d+)"
)
EXIT_RE=re.compile(r"FIRECRACKER_R3B_EXIT code=(\d+)")


def _sha256_bytes(data:bytes)->str:
    return hashlib.sha256(data).hexdigest()


def deterministic_backend(request:dict)->dict:
    if set(request)!={"operation","profile","input"}:
        raise ValueError("request fields outside bounded schema")
    if request["operation"]!="classify" or request["profile"]!="deterministic-v0":
        raise ValueError("request operation/profile not admitted")
    value=request["input"]
    if not isinstance(value,str) or not (1<=len(value)<=512):
        raise ValueError("request input invalid")
    return {
        "schema":"deterministic-inference/v1",
        "profile":"deterministic-v0",
        "output":"digest:"+hashlib.sha256(value.encode("utf-8")).hexdigest()[:24],
    }


class BrokerState:
    def __init__(self, token:str, ttl_seconds:float=30.0):
        self.token=token
        self.token_sha256=_sha256_bytes(token.encode("utf-8"))
        self.deadline=time.monotonic()+ttl_seconds
        self.accepted=0
        self.replay_rejected=0
        self.rejected=0
        self.request_sha256=None
        self.response_sha256=None
        self.lock=threading.Lock()

    def handle(self, *, authorization:str, body:bytes)->tuple[int,bytes]:
        with self.lock:
            if time.monotonic()>self.deadline:
                self.rejected+=1
                return 410,b'{"error":"capability-expired"}'
            if authorization!="Bearer "+self.token:
                self.rejected+=1
                return 401,b'{"error":"unauthorized"}'
            if self.accepted>=1:
                self.replay_rejected+=1
                return 409,b'{"error":"capability-consumed"}'
            if len(body)>4096:
                self.rejected+=1
                return 413,b'{"error":"request-too-large"}'
            try:
                request=json.loads(body.decode("utf-8"))
                response=deterministic_backend(request)
            except Exception:
                self.rejected+=1
                return 400,b'{"error":"invalid-request"}'
            response_bytes=json.dumps(response,sort_keys=True,separators=(",",":")).encode("utf-8")
            self.accepted=1
            self.request_sha256=_sha256_bytes(body)
            self.response_sha256=_sha256_bytes(response_bytes)
            return 200,response_bytes


def _handler_type(state:BrokerState):
    class Handler(http.server.BaseHTTPRequestHandler):
        server_version="R3B0"
        sys_version=""
        def log_message(self, _format, *_args):
            return
        def do_POST(self):
            if self.path!="/v1/infer":
                self.send_response(404); self.end_headers(); return
            length=int(self.headers.get("Content-Length","0"))
            body=self.rfile.read(min(length,4097))
            status,response=state.handle(
                authorization=self.headers.get("Authorization",""),
                body=body,
            )
            self.send_response(status)
            self.send_header("Content-Type","application/json")
            self.send_header("Content-Length",str(len(response)))
            self.end_headers()
            self.wfile.write(response)
    return Handler


class BrokerServer(socketserver.ThreadingMixIn,http.server.HTTPServer):
    daemon_threads=True
    allow_reuse_address=True


def _network_setup(uid:int, port:int)->dict:
    ipt=r2._iptables_bin()
    if not ipt or not shutil.which("ip") or not shutil.which("sudo") or not pathlib.Path("/dev/net/tun").exists():
        raise RuntimeError("broker network prerequisites unavailable")
    tap=f"fcr3b{os.getpid()}"[:15]
    for argv in [
        ["ip","tuntap","add","dev",tap,"mode","tap","user",str(uid)],
        ["ip","addr","add",f"{r2.TAP_IP}/{r2.CIDR}","dev",tap],
        ["ip","link","set",tap,"up"],
    ]:
        rr=r2._sudo(argv)
        if not rr["ok"]:
            raise RuntimeError(f"broker network setup failed: {argv}: {rr['stderr']}")

    rules=[
        ["-I","INPUT","1","-i",tap,"-s",r2.GUEST_IP,"-d",r2.TAP_IP,"-p","tcp","--dport",str(port),"-j","ACCEPT"],
        ["-I","INPUT","2","-i",tap,"-j","DROP"],
        ["-I","FORWARD","1","-i",tap,"-j","DROP"],
    ]
    applied=[]
    try:
        for args in rules:
            rr=r2._ipt(ipt,args)
            if not rr["ok"]:
                raise RuntimeError(f"broker firewall setup failed: {args}: {rr['stderr']}")
            applied.append(args)
    except Exception:
        _network_cleanup({"tap":tap,"iptables":ipt,"rules":applied})
        raise
    return {"tap":tap,"iptables":ipt,"rules":rules,"port":port}


def _network_cleanup(state:dict|None)->dict:
    if not state:
        return {"ok":True,"actions":[]}
    actions=[]
    ipt=state.get("iptables")
    for args in reversed(state.get("rules",[])):
        delete=list(args)
        delete[0]="-D"
        rr=r2._ipt(ipt,delete)
        actions.append({"kind":"iptables","args":delete,"ok":rr["ok"]})
    rr=r2._sudo(["ip","link","del",state["tap"]])
    actions.append({"kind":"tap-delete","ok":rr["ok"]})
    return {"ok":rr["ok"],"actions":actions}


def _ruleset(state:dict)->dict:
    out={}
    for table in ("INPUT","FORWARD"):
        rr=r2._ipt(state["iptables"],["-L",table,"-v","-n","-x"])
        out[table]=rr["stdout"] if rr["ok"] else rr["stderr"]
    return out


def _build_initramfs(init_bin:pathlib.Path,out:pathlib.Path)->None:
    import stat
    payload=b"".join([
        f1._newc_entry(".",mode=stat.S_IFDIR|0o755,ino=1,nlink=2),
        f1._newc_entry("dev",mode=stat.S_IFDIR|0o755,ino=2,nlink=2),
        f1._newc_entry("dev/console",mode=stat.S_IFCHR|0o600,ino=3,rdevmajor=5,rdevminor=1),
        f1._newc_entry("dev/vda",mode=stat.S_IFBLK|0o660,ino=4,rdevmajor=254,rdevminor=0),
        f1._newc_entry("dev/vdb",mode=stat.S_IFBLK|0o660,ino=5,rdevmajor=254,rdevminor=16),
        f1._newc_entry("newroot",mode=stat.S_IFDIR|0o755,ino=6,nlink=2),
        f1._newc_entry("init",mode=stat.S_IFREG|0o755,data=init_bin.read_bytes(),ino=7),
        f1._newc_entry("TRAILER!!!",mode=0,ino=8),
    ])
    out.write_bytes(payload)


def _debugfs(image:pathlib.Path,command:str)->dict:
    binary=shutil.which("debugfs")
    if not binary:
        return {"ok":False,"reason":"debugfs unavailable"}
    cp=subprocess.run([binary,"-w","-R",command,str(image)],capture_output=True,text=True,timeout=20,check=False)
    return {"ok":cp.returncode==0,"stdout":cp.stdout[-2000:],"stderr":cp.stderr[-2000:]}


def _preload_scratch(image:pathlib.Path, config_path:pathlib.Path)->dict:
    observations=[]
    for command in [
        f"write {GUEST_SOURCE.resolve()} /r3b.py",
        f"write {config_path.resolve()} /r3b-config.json",
    ]:
        rr=_debugfs(image,command)
        observations.append({"command_kind":"write","ok":rr["ok"],"stderr":rr.get("stderr","")})
        if not rr["ok"]:
            return {"ok":False,"observations":observations}
    return {"ok":True,"observations":observations}


def _inspect_scratch(image:pathlib.Path, work:pathlib.Path)->dict:
    debugfs=shutil.which("debugfs")
    if not debugfs:
        return {"ok":False,"reason":"debugfs unavailable"}
    result_file=work/"r3b-host-result.json"
    code,out,err=f0._run([debugfs,"-R",f"dump -p /r3b-result.json {result_file}",str(image)],timeout=20)
    if code!=0 or not result_file.exists():
        return {"ok":False,"reason":"result dump failed","stderr":err[-1000:] if err else ""}
    try:
        result=json.loads(result_file.read_text())
    except Exception as exc:
        return {"ok":False,"reason":f"result JSON invalid: {exc}"}
    stat_code,stat_out,stat_err=f0._run([debugfs,"-R","stat /r3b-config.json",str(image)],timeout=10)
    config_absent=("File not found" in (stat_out+stat_err)) or ("not found" in (stat_out+stat_err).lower())
    return {"ok":True,"result":result,"config_absent":config_absent}


def _run_jailed(*,jailer,firecracker,jail_base,vm_id,uid,gid)->dict:
    command=[
        shutil.which("sudo"),"-n",str(jailer),
        "--id",vm_id,"--exec-file",str(firecracker),
        "--uid",str(uid),"--gid",str(gid),
        "--chroot-base-dir",str(jail_base),
        "--cgroup-version","2","--new-pid-ns",
        "--resource-limit","no-file=128",
        "--","--no-api","--config-file","/vm-config.json",
    ]
    host_ns={ns:os.readlink(f"/proc/self/ns/{ns}") for ns in ("mnt","pid")}
    started=time.perf_counter()
    proc=subprocess.Popen(command,stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True)
    pid_file=jail_base/firecracker.name/vm_id/"root"/f"{firecracker.name}.pid"
    observation=None
    deadline=time.time()+12
    while time.time()<deadline:
        pid_read=j1._sudo(["cat",str(pid_file)],timeout=5)
        if pid_read["ok"]:
            try:
                observation=j1._process_observation(int(pid_read["stdout"].strip()))
            except Exception:
                observation=None
        if observation is not None and observation.get("seccomp_mode")==2:
            break
        time.sleep(0.01)
    try:
        stdout,stderr=proc.communicate(timeout=30)
    except subprocess.TimeoutExpired:
        proc.kill(); stdout,stderr=proc.communicate()
    elapsed_ms=round((time.perf_counter()-started)*1000.0,3)
    combined="\n".join(x for x in (stdout,stderr) if x)
    marker=RESULT_RE.search(combined)
    exit_marker=EXIT_RE.search(combined)
    observed=None
    if marker:
        observed={
            "first_status":int(marker.group(1)),
            "second_status":int(marker.group(2)),
            "request_sha256":marker.group(3),
            "response_sha256":marker.group(4),
            "other_host_blocked":marker.group(5)=="1",
            "metadata_blocked":marker.group(6)=="1",
        }
    uid_ok=bool(observation and observation.get("uid_fields") and observation["uid_fields"][0]==uid)
    gid_ok=bool(observation and observation.get("gid_fields") and observation["gid_fields"][0]==gid)
    seccomp_ok=bool(observation and observation.get("seccomp_mode")==2)
    pidns_ok=bool(observation and observation.get("pid_ns") not in {None,host_ns["pid"]})
    mntns_ok=bool(observation and observation.get("mnt_ns") not in {None,host_ns["mnt"]})
    clean=proc.returncode==0 and "Firecracker exiting successfully" in combined
    guest_ok=bool(observed) and observed["first_status"]==200 and observed["second_status"]==409 and observed["other_host_blocked"] and observed["metadata_blocked"] and exit_marker and int(exit_marker.group(1))==0 and clean
    return {
        "ok":guest_ok and uid_ok and gid_ok and seccomp_ok and pidns_ok and mntns_ok,
        "guest_oracle_satisfied":guest_ok,
        "uid_drop_observed":uid_ok,
        "gid_drop_observed":gid_ok,
        "seccomp_filter_observed":seccomp_ok,
        "new_pid_namespace_observed":pidns_ok,
        "mount_namespace_observed":mntns_ok,
        "clean_vmm_exit_observed":clean,
        "elapsed_ms":elapsed_ms,
        "observed":observed,
        "process_observation":observation,
        "output_tail":combined[-12000:],
    }


def run_probe(label:str)->dict:
    timer=LifecycleTimer()
    if platform.system()!="Linux" or platform.machine() not in {"x86_64","amd64"}:
        return {"schema":SCHEMA,"authority":AUTHORITY,"result":{"classification":"SETUP_REQUIRED"}}

    vm=f1._load_json(f3.VMM_MANIFEST)
    km=f1._load_json(f3.KERNEL_MANIFEST)
    um=json.loads(USERSPACE_MANIFEST.read_text())
    token=secrets.token_urlsafe(32)
    token_sha256=_sha256_bytes(token.encode("utf-8"))
    request={"operation":"classify","profile":"deterministic-v0","input":"bounded firecracker inference broker probe"}
    request_bytes=json.dumps(request,sort_keys=True,separators=(",",":")).encode("utf-8")

    identity=None
    network=None
    broker=None
    broker_thread=None
    trusted_base=pathlib.Path(f"/opt/agent-dispatch-fcr3b-{os.getpid()}")
    cleanup_network=None
    cleanup_identity=None

    with tempfile.TemporaryDirectory(prefix="firecracker-r3b-") as td:
        w=pathlib.Path(td)
        archive=w/"firecracker.tgz"; extract=w/"extract"; extract.mkdir()
        kernel=w/"vmlinux"; rootfs=w/"ubuntu.squashfs"; scratch=w/"scratch.ext4"
        init_bin=w/"init"; initrd=w/"initrd.cpio"; config=w/"vm.json"; guest_config=w/"r3b-config.json"

        guest_config.write_text(json.dumps({
            "host":r2.TAP_IP,
            "port":BROKER_PORT,
            "capability":token,
            "request":request,
        },sort_keys=True)+"\n",encoding="utf-8")

        with timer.stage("vmm_download_and_verify","venue"):
            vv=f1._download_and_verify(vm["archive_url"],vm["archive_sha256"],archive)
        with timer.stage("archive_extract","portable"):
            f0._safe_extract(archive,extract)
            firecracker=j1._find_binary(extract,f"firecracker-{vm['version']}-{vm['architecture']}")
            jailer=j1._find_binary(extract,f"jailer-{vm['version']}-{vm['architecture']}")
            firecracker.chmod(firecracker.stat().st_mode|0o111); jailer.chmod(jailer.stat().st_mode|0o111)
        with timer.stage("kernel_download_and_verify","venue"):
            kv=f1._download_and_verify(km["kernel_url"],km["kernel_sha256"],kernel)
        with timer.stage("userspace_download_and_verify","venue"):
            uv=f1._download_and_verify(um["rootfs_url"],um["rootfs_sha256"],rootfs)
        with timer.stage("bridge_init_compile","portable"):
            ic=f1._compile_init(INIT_SOURCE,init_bin)
        if not all([vv["verified"],kv["verified"],uv["verified"],ic["ok"]]):
            return {"schema":SCHEMA,"authority":AUTHORITY,"result":{"classification":"HARNESS_FAILURE"}}
        with timer.stage("initramfs_build","portable"):
            _build_initramfs(init_bin,initrd)
        with timer.stage("scratch_ext4_create","venue"):
            ss=u1._make_scratch(scratch)
        if not ss["ok"]:
            return {"schema":SCHEMA,"authority":AUTHORITY,"result":{"classification":"SETUP_REQUIRED","reason":ss["reason"]}}
        with timer.stage("scratch_preload","portable"):
            preload=_preload_scratch(scratch,guest_config)
        if not preload["ok"]:
            return {"schema":SCHEMA,"authority":AUTHORITY,"result":{"classification":"HARNESS_FAILURE","reason":"scratch preload failed"}}
        with timer.stage("ephemeral_identity_create","venue"):
            identity=j1._create_ephemeral_identity(f"fcr3b{os.getpid()}")

        execution=None; scratch_result=None; rules={}; root_immutable=False
        try:
            with timer.stage("trusted_runtime_stage","venue"):
                trusted=j1._stage_trusted_runtime(trusted_base,firecracker,jailer)
            with timer.stage("broker_network_setup","venue"):
                network=_network_setup(identity["uid"],BROKER_PORT)

            state=BrokerState(token)
            broker=BrokerServer((r2.TAP_IP,BROKER_PORT),_handler_type(state))
            broker_thread=threading.Thread(target=broker.serve_forever,kwargs={"poll_interval":0.05},daemon=True)
            broker_thread.start()

            cfg=f1._build_config(kernel,initrd,config)
            cfg["machine-config"]["mem_size_mib"]=512
            cfg["boot-source"]["kernel_image_path"]="/vmlinux"
            cfg["boot-source"]["initrd_path"]="/initrd.cpio"
            cfg["boot-source"]["boot_args"] += f" ip={r2.GUEST_IP}::{r2.TAP_IP}:255.255.255.252::eth0:off"
            cfg["drives"]=[
                {"drive_id":"userspace","path_on_host":"/ubuntu.squashfs","is_root_device":False,"is_read_only":True},
                {"drive_id":"scratch","path_on_host":"/scratch.ext4","is_root_device":False,"is_read_only":False},
            ]
            cfg["network-interfaces"]=[{"iface_id":"r3bnet0","guest_mac":"06:00:00:00:03:20","host_dev_name":network["tap"]}]
            config.write_text(json.dumps(cfg,indent=2,sort_keys=True)+"\n")

            vm_id=f"r3b-{os.getpid()}"
            jail_root=trusted["jail_base"]/trusted["firecracker"].name/vm_id/"root"
            with timer.stage("jail_resource_stage","venue"):
                staged=u2._stage_vm_resources(
                    jail_root,kernel=kernel,initrd=initrd,rootfs=rootfs,scratch=scratch,config=config,
                    uid=identity["uid"],gid=identity["gid"],
                )
            staged_root=pathlib.Path(staged["rootfs"])
            staged_scratch=pathlib.Path(staged["scratch"])
            root_before=u2._sudo_sha256(staged_root)

            with timer.stage("jailed_broker_client_lifecycle","portable"):
                execution=_run_jailed(
                    jailer=trusted["jailer"],firecracker=trusted["firecracker"],jail_base=trusted["jail_base"],
                    vm_id=vm_id,uid=identity["uid"],gid=identity["gid"],
                )

            rules=_ruleset(network)
            exported=w/"exported-scratch.ext4"
            with timer.stage("scratch_export","venue"):
                u2._export_from_jail(staged_scratch,exported)
            with timer.stage("scratch_reconciliation","portable"):
                scratch_result=_inspect_scratch(exported,w)
            root_after=u2._sudo_sha256(staged_root)
            root_immutable=root_before==root_after==um["rootfs_sha256"]

            input_drop=r2._counter_for(rules["INPUT"],network["tap"])
            forward_drop=r2._counter_for(rules["FORWARD"],network["tap"])
            allow_packets=r2._counter_for(rules["INPUT"],f"dpt:{BROKER_PORT}")
            guest=(scratch_result or {}).get("result") or {}
            token_not_logged=token not in ((execution or {}).get("output_tail") or "")
            hashes_match=bool(
                state.request_sha256==guest.get("request_sha256")==_sha256_bytes(request_bytes)
                and state.response_sha256==guest.get("response_sha256")
                and guest.get("token_sha256")==token_sha256
            )
            supported=bool(
                execution and execution["ok"]
                and scratch_result and scratch_result["ok"]
                and scratch_result.get("config_absent") is True
                and root_immutable
                and state.accepted==1
                and state.replay_rejected==1
                and state.rejected==0
                and hashes_match
                and token_not_logged
                and allow_packets>0
                and input_drop>0
                and forward_drop>0
            )

            return {
                "schema":SCHEMA,
                "authority":AUTHORITY,
                "requested_label":label,
                "result":{
                    "classification":"SUPPORTED" if supported else "ORACLE_FAILURE",
                    "minimum_authority_broker_supported":supported,
                    "rootfs_immutable":root_immutable,
                    "token_not_logged":token_not_logged,
                    "hashes_reconciled":hashes_match,
                },
                "broker":{
                    "bind":f"{r2.TAP_IP}:{BROKER_PORT}",
                    "path":"/v1/infer",
                    "accepted_calls":state.accepted,
                    "replay_rejected":state.replay_rejected,
                    "other_rejected":state.rejected,
                    "token_sha256":token_sha256,
                    "request_sha256":state.request_sha256,
                    "response_sha256":state.response_sha256,
                    "backend":"deterministic-v0",
                    "generic_proxy":False,
                    "provider_credential_present":False,
                },
                "guest":guest,
                "execution":execution,
                "scratch_reconciliation":scratch_result,
                "policy_evidence":{
                    "broker_allow_packets":allow_packets,
                    "input_drop_packets":input_drop,
                    "forward_drop_packets":forward_drop,
                },
                "lifecycle_timing":timer.receipt(),
                "next_gate":"R3b-1 may replace only the deterministic broker backend with an already-authorized real inference backend; otherwise stop NOT_REACHED.",
            }
        finally:
            if broker is not None:
                broker.shutdown(); broker.server_close()
            if broker_thread is not None:
                broker_thread.join(timeout=2)
            with timer.stage("broker_network_cleanup","venue"):
                cleanup_network=_network_cleanup(network)
            with timer.stage("jail_cleanup","venue"):
                if trusted_base.exists():
                    j1._sudo(["rm","-rf",str(trusted_base)],timeout=60)
            with timer.stage("identity_cleanup","venue"):
                cleanup_identity=j1._delete_ephemeral_identity(identity) if identity else None


def main()->int:
    p=argparse.ArgumentParser()
    p.add_argument("--label",required=True)
    p.add_argument("--out",type=pathlib.Path,required=True)
    a=p.parse_args()
    a.out.parent.mkdir(parents=True,exist_ok=True)
    try:
        receipt=run_probe(a.label)
    except Exception as exc:
        receipt={"schema":SCHEMA,"authority":AUTHORITY,"result":{"classification":"HARNESS_FAILURE","reason":f"{type(exc).__name__}: {exc}"}}
    a.out.write_text(json.dumps(receipt,indent=2,sort_keys=True)+"\n")
    print(json.dumps(receipt,indent=2,sort_keys=True))
    return 0 if receipt["result"]["classification"]=="SUPPORTED" else 1


if __name__=="__main__":
    raise SystemExit(main())
