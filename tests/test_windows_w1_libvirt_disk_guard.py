"""Adversarial host-only W1 DiskID=0 safety boundary.

All evidence is synthetic, no Windows Setup, no disk wipe, no VM created.
"""
from __future__ import annotations
import copy, unittest, uuid
import xml.etree.ElementTree as ET
from scripts.windows_w1_libvirt_disk_guard import verify_host_disk_guard, DiskGuardRefused, SIZE
from scripts.windows_w1_libvirt_domain import render_w1_libvirt_xml
from scripts.windows_w1_libvirt_plan import libvirt_w1_plan, MEDIA_SHA256, MEDIA_SIZE
from scripts.compute_guest_profile_contract import load
from pathlib import Path

UID="c31d4df2-9ab1-4ea7-b317-75b9c633b9b1"
HE=uuid.UUID(UID).hex
ROOT="/var/lib/libvirt/images/ad-w1-"+HE

def fixture():
    obs={
        "owned_root":ROOT,"libvirt_uri":"qemu:///system",
        "kvm_vcpu_exercised":True,"host_passthrough_supported":True,
        "secureboot_firmware_observed":True,"enrolled_keys_observed":True,
        "swtpm2_startup_exercised":True,"owned_isolated_network_observed":True,
        "domain_uuid_absent":True,"owned_root_absent":True,
        "installer_media_digest_verified":True,"unattended_seed_secret_free":True,
        "windows_wipe_target_is_single_run_owned_disk":True,
        "installer_media_sha256":MEDIA_SHA256,"installer_media_size_bytes":MEDIA_SIZE,
        "network":"ad-w1-"+HE,"unattended_seed_sha256":"f"*64,
    }
    p=libvirt_w1_plan(load(Path("config/compute-guest-profiles.json")),obs,UID)
    xml=render_w1_libvirt_xml(p)
    info={"path":ROOT+"/system.qcow2","realpath":ROOT+"/system.qcow2",
          "regular_file":True,"symlink":False,"parent_symlink":False,
          "qemu_img":{"format":"qcow2","virtual-size":SIZE}}
    return xml,info

def modify(xml,fx):
    e=ET.fromstring(xml);fx(e)
    return ET.tostring(e,encoding="unicode")

class HostGuardAdversarial(unittest.TestCase):
    def test_positive_host_only_no_wipe_admission(self):
        x,i=fixture()
        r=verify_host_disk_guard(x,run_uuid=UID,image=i)
        self.assertEqual(r["classification"],"HOST_SINGLE_OWNED_DISK_CONFIRMED")
        self.assertTrue(r["one_writable_host_disk"])
        self.assertFalse(r["guest_disk_zero_identity_confirmed"])
        self.assertFalse(r["windows_unattended_wipe_authorized"])

    def test_run_uuid_source_and_symlink_guards(self):
        x,i=fixture()
        for wrong in ("c31d4df2-9ab1-4ea7-b317-75b9c633b9b2", "not-a-uuid"):
            with self.subTest(uuid=wrong),self.assertRaises(DiskGuardRefused):
                verify_host_disk_guard(x,run_uuid=wrong,image=i)
        for key,bad in (("path","/dev/sda"),("realpath","/tmp/symlink"),
                        ("regular_file",False),("symlink",True),("parent_symlink",True)):
            b=copy.deepcopy(i);b[key]=bad
            with self.subTest(key=key),self.assertRaises(DiskGuardRefused):
                verify_host_disk_guard(x,run_uuid=UID,image=b)

    def test_reject_unknown_wrong_or_backed_disk_image(self):
        x,i=fixture()
        variants=(
            ("format","raw"),("virtual-size",32*1024**3),
            ("virtual-size",True),("backing-filename","/unowned/master.qcow2"),
            ("full-backing-filename","/tmp/parent.qcow2"),
        )
        for k,bad in variants:
            z=copy.deepcopy(i);z["qemu_img"][k]=bad
            with self.subTest(key=k),self.assertRaises(DiskGuardRefused):
                verify_host_disk_guard(x,run_uuid=UID,image=z)

    def test_extra_or_wrong_system_disk_is_refused(self):
        x,i=fixture()
        changes=(
            lambda e:e.find("./devices/disk/source").set("file","/dev/sda"),
            lambda e:e.find("./devices/disk/target").set("bus","virtio"),
            lambda e:e.find("./devices/disk").set("device","lun"),
            lambda e:e.find("./devices/disk/driver").set("type","raw"),
            lambda e:e.find("./devices").append(copy.deepcopy(e.find("./devices/disk"))),
            lambda e:e.find("./devices").append(ET.Element("hostdev")),
        )
        for idx,fn in enumerate(changes):
            with self.subTest(case=idx),self.assertRaises(DiskGuardRefused):
                verify_host_disk_guard(modify(x,fn),run_uuid=UID,image=i)

    def test_optical_remains_owned_readonly_and_not_a_second_disk(self):
        x,i=fixture()
        mods=(
            lambda e:e.findall("./devices/disk")[1].remove(e.findall("./devices/disk")[1].find("readonly")),
            lambda e:e.findall("./devices/disk")[2].find("source").set("file","/etc/passwd"),
            lambda e:e.findall("./devices/disk")[1].find("target").set("bus","virtio"),
            lambda e:e.findall("./devices/disk")[2].set("device","disk"),
        )
        for idx,fn in enumerate(mods):
            with self.subTest(case=idx),self.assertRaises(DiskGuardRefused):
                verify_host_disk_guard(modify(x,fn),run_uuid=UID,image=i)

    def test_qemu_namespaced_commandline_can_not_smuggle_additional_disk(self):
        xml,image=fixture()
        ns="http://libvirt.org/schemas/domain/qemu/1.0"
        def inject(dom):
            ext=ET.SubElement(dom,"{"+ns+"}commandline")
            ET.SubElement(ext,"{"+ns+"}arg",{"value":"-drive"})
            ET.SubElement(ext,"{"+ns+"}arg",{"value":"file=/dev/sda,if=none"})
        tampered=modify(xml,inject)
        with self.assertRaises(DiskGuardRefused):
            verify_host_disk_guard(tampered,run_uuid=UID,image=image)

    def test_other_unowned_guest_interfaces_refused(self):
        x,i=fixture()
        for device in ("hostdev","filesystem","redirdev"):
            y=modify(x,lambda e:e.find("./devices").append(ET.Element(device)))
            with self.subTest(device=device),self.assertRaises(DiskGuardRefused):
                verify_host_disk_guard(y,run_uuid=UID,image=i)

if __name__=="__main__":
    unittest.main()
