#!/usr/bin/env python3
"""Recover ONLY a killed, disposable, owned public KVM test process.

No private WinBot source or production agent. Reconciles exact native UUID,
name, bridge, disk and overlay backing BEFORE ANY native mutation. A refusal
never widens resource scope. Does not scan/reap unrelated resources.
"""
from __future__ import annotations
import json
import os
import pathlib
import re
import shutil
import stat
import subprocess
import sys
import uuid
import xml.etree.ElementTree as ET

BASE=pathlib.Path("/var/lib/libvirt/images")
class ReaperRefused(ValueError):pass
def need(ok,why):
    if not ok:raise ReaperRefused(why)
def virsh(*args):
    return subprocess.run(("virsh","-c","qemu:///system",*args),text=True,
                          capture_output=True,check=False,timeout=30)
def text(*args):
    r=virsh(*args)
    need(r.returncode==0,"native read refused: "+args[0])
    return r.stdout
def empty_directory_or_one_owned_file(root,filename):
    st=os.lstat(root)
    need(stat.S_ISDIR(st.st_mode) and not stat.S_ISLNK(st.st_mode),
         "owned directory is not ordinary directory")
    need(set(os.listdir(root))=={filename},"unknown files in owned directory")
    f=os.lstat(root/filename)
    need(stat.S_ISREG(f.st_mode) and f.st_nlink==1,
         "non-regular, linked, or foreign owned file")
def classify(manifest_path):
    p=pathlib.Path(manifest_path)
    need(str(p).startswith("/tmp/winbot-crash-") and
         p.name=="ownership-manifest.json" and p.parent.parent==pathlib.Path("/tmp"),
         "recovery manifest must be direct owned /tmp workcell")
    # No path-following and no ambient world-readable mutable claim.
    # The janitor must not trust a linked/replaced owner manifest even when
    # it contains otherwise syntactically correct run UUIDs and paths.
    directory=os.lstat(p.parent)
    need(stat.S_ISDIR(directory.st_mode) and
         stat.S_IMODE(directory.st_mode)&0o077==0 and
         directory.st_uid==os.geteuid(),
         "owner manifest directory is foreign or not private")
    dfd=os.open(p.parent,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC)
    try:
        fd=os.open(p.name,os.O_RDONLY|os.O_NOFOLLOW|os.O_CLOEXEC,dir_fd=dfd)
        try:
            before=os.fstat(fd)
            need(stat.S_ISREG(before.st_mode) and before.st_nlink==1 and
                 stat.S_IMODE(before.st_mode)&0o077==0 and
                 1<=before.st_size<=8192 and
                 before.st_uid==os.geteuid(),
                 "foreign, linked or unbounded recovery manifest")
            with os.fdopen(fd,"rb",closefd=False) as stream:
                payload=stream.read(8193)
            after=os.fstat(fd)
            at_path=os.stat(p.name,dir_fd=dfd,follow_symlinks=False)
            tracked=("st_dev","st_ino","st_size","st_mtime_ns","st_ctime_ns","st_nlink")
            need(len(payload)==before.st_size and
                 all(getattr(before,k)==getattr(after,k)==getattr(at_path,k)
                     for k in tracked),
                 "recovery manifest changed or was rebound")
        finally: os.close(fd)
    finally: os.close(dfd)
    def distinct_pairs(pairs):
        result={}
        for k,v in pairs:
            need(k not in result,"duplicate manifest key")
            result[k]=v
        return result
    info=json.loads(payload,object_pairs_hook=distinct_pairs)
    need(info.get("schema")=="winbot-public-synthetic-owner-manifest/v1" and
         info.get("classification")=="DISPOSABLE_RUN_OWNED_ONLY" and
         info.get("windows_or_private_winbot_source") is False and
         info.get("production_or_physical_host_authorized") is False,
         "untrusted or admitted manifest type")
    uid=info.get("vm_uuid")
    try: u=uuid.UUID(uid)
    except (ValueError,TypeError,AttributeError) as e:
        raise ReaperRefused("bad run UUID") from e
    need(u.version==4 and str(u)==uid,"run owner must be canonical UUIDv4")
    hx=u.hex
    root=BASE/("winbot-rdte-"+hx)
    parent=BASE/("winbot-synthetic-master-"+hx)
    overlay=root/"system.qcow2"
    master=parent/"accepted-master.qcow2"
    name="WinBot-OverlayProbe-"+hx
    net="winbot-rdte-"+hx
    bridge="wb"+hx[:10]
    try: nu=uuid.UUID(info.get("network_uuid"))
    except (ValueError,TypeError,AttributeError) as e:
        raise ReaperRefused("bad network UUID") from e
    need(nu.version==4 and str(nu)==info.get("network_uuid"),"noncanonical network UUID")
    expected={"domain_name":name,"network_name":net,"bridge_name":bridge,
              "overlay_root":str(root),"master_root":str(parent),
              "overlay_file":str(overlay),"master_file":str(master)}
    need(all(info.get(k)==v for k,v in expected.items()),"manifest owner/path binding drift")
    empty_directory_or_one_owned_file(root,"system.qcow2")
    empty_directory_or_one_owned_file(parent,"accepted-master.qcow2")
    xml=ET.fromstring(text("dumpxml",uid))
    need(xml.tag=="domain" and xml.get("type")=="kvm" and
         xml.findtext("name")==name and xml.findtext("uuid")==uid,
         "native VM identity drift")
    need(not any(isinstance(node.tag,str) and node.tag.startswith("{")
                 for node in xml.iter()),"QEMU extension native XML rejected")
    devices=xml.find("devices")
    need(devices is not None and not any(devices.find(k) is not None for k in
         ("hostdev","filesystem","redirdev")),"native host passthrough refused")
    disks=xml.findall("./devices/disk")
    need(len(disks)==1 and disks[0].get("device")=="disk" and
         disks[0].get("type")=="file","unexpected native disk inventory")
    d=disks[0]
    ds=d.find("source");df=d.find("driver")
    need(ds is not None and ds.get("file")==str(overlay) and
         df is not None and df.get("type")=="qcow2","wrong overlay source")
    backs=d.findall("backingStore")
    state=virsh("domstate",uid)
    need(state.returncode==0,"native owned VM state unreadable")
    stopped=state.stdout.strip().lower()=="shut off"
    # libvirt may omit runtime-resolved backing metadata from dumpxml once a
    # guest has stopped. NEVER accept an omitted chain for a running guest.
    # Even for a stopped guest, the independent QEMU backing-chain inspection
    # below MUST still prove exactly overlay -> owned synthetic master.
    if len(backs)==0:
        need(stopped,"running guest missing native backing proof")
    else:
        need(len(backs)==1 and backs[0].get("type")=="file",
             "ambiguous native backing chain")
        bs=backs[0].find("source");bf=backs[0].find("format")
        need(bs is not None and bs.get("file")==str(master) and
             bf is not None and bf.get("type")=="qcow2",
             "backing source does not bind owned synthetic master")
        tail=backs[0].findall("backingStore")
        need(len(tail)==1 and not tail[0].attrib and not list(tail[0]),
             "not a terminated two-image chain")
    nic=xml.findall("./devices/interface")
    need(len(nic)==1 and nic[0].get("type")=="network" and
         nic[0].find("source") is not None and
         nic[0].find("source").get("network")==net and
         nic[0].find("model") is not None and
         nic[0].find("model").get("type")=="e1000",
         "unexpected NIC or foreign network")
    network=ET.fromstring(text("net-dumpxml",net))
    nb=network.find("bridge")
    need(network.tag=="network" and network.findtext("uuid")==info["network_uuid"] and
         network.findtext("name")==net and nb is not None and
         nb.get("name")==bridge and nb.get("stp")=="off" and
         network.find("forward") is None and
         not any(network.find(x) is not None for x in
                 ("ip","route","dns","portgroup","virtualport")),
         "native owned network identity or isolation changed")
    qc=subprocess.run(("qemu-img","info","-U","--output=json","--backing-chain",
                       str(overlay)),text=True,capture_output=True,timeout=40,check=False)
    need(qc.returncode==0,"cannot observe owned QEMU image chain")
    chain=json.loads(qc.stdout)
    need(isinstance(chain,list) and len(chain)==2 and
         chain[0].get("filename")==str(overlay) and
         chain[0].get("backing-filename")==str(master) and
         chain[1].get("filename")==str(master) and
         not chain[1].get("backing-filename"),
         "real QEMU backing chain drift")
    return {"uid":uid,"name":name,"network":net,"bridge":bridge,
            "overlay":root,"master":parent,"network_uuid":info["network_uuid"]}

def main(manifest):
    try:
        owner=classify(manifest)
    except (OSError,ValueError,subprocess.SubprocessError,ET.ParseError) as ex:
        print("REAPER_REFUSAL_BEFORE_MUTATION: "+str(ex),file=sys.stderr)
        return 7
    errors=[]
    state=virsh("domstate",owner["uid"])
    if state.returncode:errors.append("no domain state")
    elif state.stdout.strip().lower()!="shut off":
        x=virsh("destroy",owner["uid"])
        if x.returncode:errors.append("native destroy failed")
    if not errors:
        x=virsh("undefine",owner["uid"])
        if x.returncode:errors.append("native undefine failed")
    if not errors:
        n=virsh("net-info",owner["network"])
        if n.returncode:errors.append("native net-info failed")
        elif any(line.strip().lower().startswith("active:") and
                 line.split(":",1)[1].strip().lower()=="yes"
                 for line in n.stdout.splitlines()):
            x=virsh("net-destroy",owner["network"])
            if x.returncode:errors.append("native net-destroy failed")
        if not errors:
            x=virsh("net-undefine",owner["network"])
            if x.returncode:errors.append("native net-undefine failed")
    if not errors and virsh("dominfo",owner["uid"]).returncode!=0 and \
       virsh("net-info",owner["network"]).returncode!=0:
        for k in ("overlay","master"):
            try:shutil.rmtree(owner[k])
            except OSError as e:errors.append("owned cleanup failed: "+type(e).__name__)
    report={"schema":"winbot-public-sigkill-recovery/v1",
            "classification":"SYNTHETIC_CRASH_JANITOR_OWNED_ONLY",
            "recovery_errors":errors,
            "domain_absent":virsh("dominfo",owner["uid"]).returncode!=0,
            "network_absent":virsh("net-info",owner["network"]).returncode!=0,
            "overlay_absent":not owner["overlay"].exists(),
            "master_fixture_absent":not owner["master"].exists(),
            "windows_or_winbot_guest_qualified":False,
            "product_cleanup_agent_admitted":False,
            "physical_or_production_deployed":False}
    pathlib.Path(manifest).parent.joinpath("recovery.json").write_text(
        json.dumps(report,sort_keys=True,indent=2)+"\n")
    passed=not errors and all(report[k] for k in
          ("domain_absent","network_absent","overlay_absent","master_fixture_absent"))
    return 0 if passed else 3
if __name__=="__main__":
    if len(sys.argv)!=2:raise SystemExit(8)
    raise SystemExit(main(sys.argv[1]))
