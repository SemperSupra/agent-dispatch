#!/usr/bin/env python3
"""Public-safe libvirt qcow2 backing-chain reality probe; no WinBot private code.

ONE disposable KVM VM, ONE independently run-owned qcow2 overlay and ONE
synthetic master in a separate run-owned root. No Windows, private source,
credentials, WinBot Apply admission, production hypervisor, or storage wipe.
"""
from __future__ import annotations
import hashlib, json, os, pathlib, shutil, stat, subprocess, sys, time, uuid
import xml.etree.ElementTree as ET

OUT = pathlib.Path("/tmp/winbot-libvirt-overlay-readback")
BASE = pathlib.Path("/var/lib/libvirt/images")
def command(*args,check=True):
    return subprocess.run(args,check=check,text=True,stdout=subprocess.PIPE,
                          stderr=subprocess.PIPE,timeout=35)
def virsh(*args,check=True):return command("virsh","-c","qemu:///system",*args,check=check)
def emit(name,data):
    (OUT/name).write_text(json.dumps(data,sort_keys=True,indent=2)+"\n")
def sha(p):
    h=hashlib.sha256()
    with open(p,"rb") as f:
        for chunk in iter(lambda:f.read(2**20),b""):h.update(chunk)
    return h.hexdigest()
def main():
    if OUT.exists(): raise RuntimeError("preexisting evidence directory")
    OUT.mkdir(mode=0o700)
    ident=str(uuid.uuid4()); hx=uuid.UUID(ident).hex
    master_root=BASE/("winbot-synthetic-master-"+hx)
    owned_root=BASE/("winbot-rdte-"+hx)
    name="WinBot-OverlayProbe-"+hx
    net="winbot-rdte-"+hx
    bridge="wb"+hx[:10]
    master=master_root/"accepted-master.qcow2"
    overlay=owned_root/"system.qcow2"
    created=[];defined=False;started=False;net_defined=False;net_started=False;err=None
    try:
        if (master_root.exists() or owned_root.exists() or
            virsh("dominfo",ident,check=False).returncode==0 or
            virsh("net-info",net,check=False).returncode==0):
            raise ValueError("refuse preexisting identity")
        for root in (master_root,owned_root):
            root.mkdir(mode=0o750);created.append(root)
        command("qemu-img","create","-f","qcow2",str(master),"1G")
        master_before=sha(master)
        command("qemu-img","create","-f","qcow2","-F","qcow2",
                "-b",str(master),str(overlay))
        image_info=json.loads(command("qemu-img","info","--output=json",
                                     str(overlay)).stdout)
        if (image_info.get("format")!="qcow2" or
            image_info.get("backing-filename")!=str(master) or
            image_info.get("backing-filename-format")!="qcow2"):
            raise ValueError("qemu-img overlay source mismatch")
        for root in (master_root,owned_root):
            shutil.chown(root,user="libvirt-qemu",group="kvm")
        for p in (master,overlay):
            shutil.chown(p,user="libvirt-qemu",group="kvm")
        n=ET.Element("network")
        ET.SubElement(n,"name").text=net
        ET.SubElement(n,"uuid").text=str(uuid.uuid4())
        ET.SubElement(n,"bridge",{"name":bridge,"stp":"off","delay":"0"})
        (OUT/"network.xml").write_text(ET.tostring(n,encoding="unicode")+"\n")
        virsh("net-define",str(OUT/"network.xml"));net_defined=True
        virsh("net-start",net);net_started=True
        (OUT/"network-realized.xml").write_text(virsh("net-dumpxml",net).stdout)
        d=ET.Element("domain",{"type":"kvm"})
        ET.SubElement(d,"name").text=name
        ET.SubElement(d,"uuid").text=ident
        ET.SubElement(d,"memory",{"unit":"MiB"}).text="512"
        ET.SubElement(d,"vcpu").text="1"
        boot=ET.SubElement(d,"os")
        ET.SubElement(boot,"type",{"arch":"x86_64","machine":"q35"}).text="hvm"
        ET.SubElement(d,"cpu",{"mode":"host-passthrough"})
        devices=ET.SubElement(d,"devices")
        ET.SubElement(devices,"emulator").text="/usr/bin/qemu-system-x86_64"
        disk=ET.SubElement(devices,"disk",{"type":"file","device":"disk"})
        ET.SubElement(disk,"driver",{"name":"qemu","type":"qcow2"})
        ET.SubElement(disk,"source",{"file":str(overlay)})
        ET.SubElement(disk,"target",{"dev":"sda","bus":"sata"})
        nic=ET.SubElement(devices,"interface",{"type":"network"})
        ET.SubElement(nic,"source",{"network":net})
        ET.SubElement(nic,"model",{"type":"e1000"})
        (OUT/"requested.xml").write_text(ET.tostring(d,encoding="unicode")+"\n")
        command("virt-xml-validate",str(OUT/"requested.xml"),"domain")
        virsh("define",str(OUT/"requested.xml"));defined=True
        (OUT/"defined.xml").write_text(virsh("dumpxml",ident).stdout)
        virsh("start",ident);started=True
        time.sleep(2)
        if virsh("domstate",ident).stdout.strip()!="running":
            raise ValueError("owned guest not running")
        live=virsh("dumpxml",ident).stdout
        (OUT/"running.xml").write_text(live)
        tree=ET.fromstring(live)
        devs=tree.findall("./devices/disk")
        if len(devs)!=1 or devs[0].get("device")!="disk":
            raise ValueError("expected one native disk")
        source=devs[0].find("source")
        if source is None or source.get("file")!=str(overlay):
            raise ValueError("native source drift")
        backs=devs[0].findall("backingStore")
        if len(backs)!=1:
            raise ValueError("native backing chain not uniquely represented")
        back=backs[0]
        bsource=back.find("source")
        if bsource is None or bsource.get("file")!=str(master):
            raise ValueError("native backing source not exact synthetic master")
        nested=back.find("backingStore")
        nested_shape=None if nested is None else {
            "attributes":dict(nested.attrib),
            "child_tags":[x.tag for x in nested],
        }
        if nested is not None and (nested.attrib or list(nested)):
            raise ValueError("nested nonterminal backing chain: refuse")
        interfaces=tree.findall("./devices/interface")
        if (len(interfaces)!=1 or interfaces[0].get("type")!="network" or
            interfaces[0].find("source") is None or
            interfaces[0].find("source").get("network")!=net or
            interfaces[0].find("model") is None or
            interfaces[0].find("model").get("type")!="e1000"):
            raise ValueError("live network must be a single run-owned E1000")
        actual_net=ET.fromstring((OUT/"network-realized.xml").read_text())
        if actual_net.find("forward") is not None or actual_net.findtext("name")!=net:
            raise ValueError("native network is not run-owned or isolated")
        # Independent public fixture: verify the *actual* qemu-img backing
        # chain, not just libvirt's rendered XML. No private WinBot source.
        # -U is QEMU read-only force-share for metadata inspection while its
        # own disposable guest holds the image open; not a write-lock override.
        qc=command("qemu-img","info","-U","--output=json",
                   "--backing-chain",str(overlay),check=False)
        if qc.returncode:
            raise ValueError("read-only QEMU image chain read failed: "+qc.stderr[:350])
        chain=json.loads(qc.stdout)
        if (not isinstance(chain,list) or len(chain)!=2 or
            chain[0].get("filename")!=str(overlay) or
            chain[0].get("format")!="qcow2" or
            chain[0].get("backing-filename")!=str(master) or
            chain[1].get("filename")!=str(master) or
            chain[1].get("format")!="qcow2" or
            chain[1].get("backing-filename")):
            raise ValueError("actual QEMU image chain differs from native XML")

        # Rejected decoys are created ONLY in the already run-owned synthetic
        # workset. Neither can be mistaken for a single-link regular master.
        def candidate_is_single_regular(p):
            observed=os.lstat(p)
            return stat.S_ISREG(observed.st_mode) and observed.st_nlink==1
        if not candidate_is_single_regular(master):
            raise ValueError("master is not a single-link regular file")
        link=owned_root/"symlink-decoy.qcow2"
        link.symlink_to(master)
        try:
            if candidate_is_single_regular(link):
                raise ValueError("unowned source symlink was mistakenly accepted")
        finally:
            link.unlink()
        hardlink=owned_root/"hardlink-decoy.qcow2"
        os.link(master,hardlink)
        try:
            if candidate_is_single_regular(master) or candidate_is_single_regular(hardlink):
                raise ValueError("unowned source hardlink was mistakenly accepted")
        finally:
            hardlink.unlink()
        if not candidate_is_single_regular(master):
            raise ValueError("master source did not recover original link identity")
        if sha(master)!=master_before:
            raise ValueError("master content mutated")
        emit("qemu-native-master-provenance.json",{
            "schema":"winbot-public-qemu-master-source-proof/v1",
            "classification":"RUN_OWNED_SYNTHETIC_MASTER_CHAIN_ONLY",
            "qemu_chain_entries":len(chain),
            "native_xml_overlay_and_qemu_chain_match":True,
            "master_image_filename":str(master),
            "overlay_image_filename":str(overlay),
            "master_digest_before_and_after_equal":True,
            "single_link_regular_file":True,
            "symlink_decoy_rejected":True,
            "hardlink_decoy_rejected":True,
            "private_winbot_code_executed":False,
            "windows_or_winbot_guest_qualified":False,
            "production_master_admitted":False
        })
        emit("backing-shape.json",{
            "schema":"winbot-native-libvirt-backing-observation/v1",
            "classification":"SYNTHETIC_LIVE_NATIVE_BACKING_READBACK_ONLY",
            "run_uuid":ident,"master_path":str(master),"overlay_path":str(overlay),
            "master_sha256_unchanged":True,
            "native_network_name":net,"native_network_isolated":True,
            "native_nic_model":"e1000",
            "backing_attributes":dict(back.attrib),
            "backing_format":None if back.find("format") is None else
                  dict(back.find("format").attrib),
            "backing_source":dict(bsource.attrib),
            "terminal_backing_marker":nested_shape,
            "actual_kvm_guest_running":True,
            "windows_guest_qualified":False,
            "winbot_private_source_executed":False,
            "product_provider_admitted":False,
            "windows_install_or_disk_wipe_authorized":False,
        })
        print("LIVE NATIVE QCOW2 OVERLAY READBACK PASS (no Windows or WinBot)")
    except Exception as ex:
        err=type(ex).__name__+": "+str(ex)
        emit("error.json",{"classification":"HARNESS_OR_ENVIRONMENT_FAILURE",
                           "message":err[:1500]})
        print(err,file=sys.stderr)
    finally:
        problems=[]
        if started:
            x=virsh("destroy",ident,check=False)
            if x.returncode:problems.append("destroy: "+x.stderr[:200])
        if defined:
            x=virsh("undefine",ident,check=False)
            if x.returncode:problems.append("undefine: "+x.stderr[:200])
        if net_started:
            x=virsh("net-destroy",net,check=False)
            if x.returncode:problems.append("net-destroy: "+x.stderr[:200])
        if net_defined:
            x=virsh("net-undefine",net,check=False)
            if x.returncode:problems.append("net-undefine: "+x.stderr[:200])
        for root in reversed(created):
            try:shutil.rmtree(root)
            except Exception as ex:problems.append(type(ex).__name__+": "+str(ex))
        present=virsh("dominfo",ident,check=False).returncode==0
        network_present=virsh("net-info",net,check=False).returncode==0
        cleanup={"schema":"winbot-native-overlay-cleanup/v1",
                 "domain_absent":not present,"owned_network_absent":not network_present,
                 "owned_overlay_absent":not owned_root.exists(),
                 "owned_master_fixture_absent":not master_root.exists(),
                 "problems":problems,"prior_failure":err}
        emit("cleanup.json",cleanup)
        if not all((cleanup["domain_absent"],cleanup["owned_network_absent"],cleanup["owned_overlay_absent"],
                    cleanup["owned_master_fixture_absent"])) or problems:
            err="NATIVE_CLEANUP_FAILED"
    return 0 if err is None else 3
if __name__=="__main__":raise SystemExit(main())
