#!/usr/bin/env python3
"""Public-only negative oracle against actual owned libvirt native readback.

Reads a real disposable VM receipt captured by winbot_public_overlay_readback;
does not import or publish WinBot private code. No VM lifecycle/mutation here.
"""
from __future__ import annotations
import copy, hashlib, json, pathlib, xml.etree.ElementTree as ET
OUT=pathlib.Path("/tmp/winbot-libvirt-overlay-readback")
def reject_if_unowned(xml:str, *, overlay:str, master:str, run_uuid:str)->bool:
    """True only for exactly one owned qcow2->accepted qcow2 master chain."""
    try:root=ET.fromstring(xml)
    except ET.ParseError:return False
    if any(isinstance(x.tag,str) and x.tag.startswith("{") for x in root.iter()):return False
    disks=root.findall("./devices/disk")
    if len(disks)!=1:return False
    d=disks[0]
    if d.get("type")!="file" or d.get("device")!="disk":return False
    drv=d.find("driver");src=d.find("source")
    if drv is None or src is None or drv.get("type")!="qcow2" or src.get("file")!=overlay:return False
    backs=d.findall("backingStore")
    if len(backs)!=1:return False
    b=backs[0];fmt=b.find("format");bsource=b.find("source")
    if b.get("type")!="file" or fmt is None or fmt.get("type")!="qcow2" or bsource is None or bsource.get("file")!=master:return False
    if any(v.tag not in {"source","format","backingStore"} for v in b):return False
    terminals=b.findall("backingStore")
    if len(terminals)>1:return False
    if terminals and (terminals[0].attrib or list(terminals[0]) or (terminals[0].text or "").strip()):return False
    if root.findall("./devices/hostdev") or root.findall("./devices/filesystem") or root.findall("./devices/redirdev"):return False
    interfaces=root.findall("./devices/interface")
    # Fixture binds network identity to the *same* run UUID that owns the overlay.
    import uuid
    owner_net="winbot-rdte-"+uuid.UUID(run_uuid).hex
    if len(interfaces)!=1 or interfaces[0].get("type")!="network":return False
    interface_source=interfaces[0].find("source")
    nic_model=interfaces[0].find("model")
    if interface_source is None or interface_source.get("network")!=owner_net or nic_model is None or nic_model.get("type")!="e1000":return False
    return True
def main():
    evidence=json.loads((OUT/"backing-shape.json").read_text())
    xml=(OUT/"running.xml").read_text()
    overlay=evidence["overlay_path"];master=evidence["master_path"]
    root=ET.fromstring(xml)
    assert reject_if_unowned(xml,overlay=overlay,master=master,run_uuid=evidence["run_uuid"]),"baseline native XML rejected"
    cases={}
    def run_case(name,fn):
        elt=copy.deepcopy(root);fn(elt);s=ET.tostring(elt,encoding="unicode")
        cases[name]=not reject_if_unowned(s,overlay=overlay,master=master,run_uuid=evidence["run_uuid"])
        assert cases[name],name+" was incorrectly accepted"
    run_case("foreign_overlay",lambda r:r.find("./devices/disk/source").set("file","/dev/sda"))
    run_case("wrong_master",lambda r:r.find("./devices/disk/backingStore/source").set("file","/srv/unowned/master.qcow2"))
    run_case("wrong_master_format",lambda r:r.find("./devices/disk/backingStore/format").set("type","raw"))
    run_case("missing_backing",lambda r:r.find("./devices/disk").remove(r.find("./devices/disk/backingStore")))
    run_case("nested_chain",lambda r:ET.SubElement(r.find("./devices/disk/backingStore/backingStore"),"source",{"file":"/srv/unowned/parent.qcow2"}))
    run_case("foreign_extra_disk",lambda r:r.find("./devices").append(copy.deepcopy(r.find("./devices/disk"))))
    run_case("direct_host_access",lambda r:r.find("./devices").append(ET.Element("hostdev")))
    def namespace(r):
        ns="http://libvirt.org/schemas/domain/qemu/1.0"
        x=ET.SubElement(r,"{"+ns+"}commandline")
        ET.SubElement(x,"{"+ns+"}arg",{"value":"-drive"})
        ET.SubElement(x,"{"+ns+"}arg",{"value":"file=/dev/sda,if=none"})
    run_case("qemu_escape_hatch",namespace)
    run_case("foreign_network",lambda r:r.find("./devices/interface/source").set("network","default"))
    run_case("wrong_nic",lambda r:r.find("./devices/interface/model").set("type","virtio"))
    run_case("extra_nic",lambda r:r.find("./devices").append(copy.deepcopy(r.find("./devices/interface"))))
    receipt={
      "schema":"winbot-public-native-chain-negative-batch/v1",
      "classification":"REAL_NATIVE_XML_PLUS_SYNTHETIC_NEGATIVE_MUTATIONS",
      "base_run_uuid":evidence["run_uuid"],
      "real_native_source_sha256":hashlib.sha256(xml.encode()).hexdigest(),
      "accepted_master_and_owned_overlay":True,
      "rejected_adversarial_variants":cases,
      "private_winbot_source_executed":False,
      "winbot_provider_admitted":False,
      "windows_guest_qualified":False,"disk_wipe_authorized":False
    }
    (OUT/"negative-matrix.json").write_text(json.dumps(receipt,sort_keys=True,indent=2)+"\n")
    print("Native XML negative matrix PASS",len(cases))
if __name__=="__main__":main()
