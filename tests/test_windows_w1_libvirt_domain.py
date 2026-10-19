"""Inert Windows W1 KVM XML: exact owned disk, media, SecureBoot, TPM, network.

No libvirt action, guest boot, ISO download, or Windows/WinBot acceptance.
"""
import copy
import pathlib
import unittest
import uuid
import xml.etree.ElementTree as ET

from scripts.compute_guest_profile_contract import load
from scripts.windows_w1_libvirt_plan import libvirt_w1_plan, MEDIA_SHA256, MEDIA_SIZE
from scripts.windows_w1_libvirt_domain import render_w1_libvirt_xml, DomainRenderRefused

RUN_ID = "c31d4df2-9ab1-4ea7-b317-75b9c633b9b1"
RUNHEX = uuid.UUID(RUN_ID).hex
ROOT = "/var/lib/libvirt/images/ad-w1-" + RUNHEX


def observed():
    return {
        "owned_root": ROOT, "libvirt_uri": "qemu:///system",
        "kvm_vcpu_exercised": True, "host_passthrough_supported": True,
        "secureboot_firmware_observed": True, "enrolled_keys_observed": True,
        "swtpm2_startup_exercised": True, "owned_isolated_network_observed": True,
        "domain_uuid_absent": True, "owned_root_absent": True,
        "installer_media_digest_verified": True, "unattended_seed_secret_free": True,
        "windows_wipe_target_is_single_run_owned_disk": True,
        "installer_media_sha256": MEDIA_SHA256,
        "installer_media_size_bytes": MEDIA_SIZE,
        "network": "ad-w1-" + RUNHEX,
        "unattended_seed_sha256": "f" * 64,
    }


class DomainRendering(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.plan = libvirt_w1_plan(load(pathlib.Path("config/compute-guest-profiles.json")),
                                   observed(), RUN_ID)

    def test_exact_inert_xml_deterministic_and_one_writable_disk(self):
        xml = render_w1_libvirt_xml(self.plan)
        self.assertEqual(xml, render_w1_libvirt_xml(self.plan))
        root = ET.fromstring(xml)
        self.assertEqual(root.attrib["type"], "kvm")
        self.assertEqual(root.findtext("uuid"), RUN_ID)
        self.assertEqual(root.findtext("./os/loader"),
                         "/usr/share/OVMF/OVMF_CODE_4M.secboot.fd")
        self.assertEqual(root.find("./os/loader").get("secure"), "yes")
        self.assertEqual(root.find("./features/smm").get("state"), "on")
        self.assertEqual(root.find("./devices/tpm/backend").get("version"), "2.0")
        self.assertEqual(root.find("./cpu").get("mode"), "host-passthrough")
        disks = root.findall("./devices/disk")
        self.assertEqual(len(disks), 3)
        writable = [d for d in disks if d.find("readonly") is None]
        self.assertEqual(len(writable), 1)
        self.assertEqual(writable[0].get("device"), "disk")
        self.assertEqual(writable[0].find("source").get("file"), ROOT + "/system.qcow2")
        self.assertEqual(writable[0].find("target").get("bus"), "sata")
        self.assertEqual([d.find("boot").get("order") for d in disks if d.find("boot") is not None],
                         ["2", "1"])
        self.assertEqual(root.find("./devices/interface/source").get("network"), "ad-w1-" + RUNHEX)
        self.assertEqual(root.find("./devices/serial/source").get("path"), ROOT + "/serial.log")
        self.assertEqual(root.find("./devices/graphics").get("listen"), "127.0.0.1")

    def test_fails_closed_on_wrong_provider_or_claimed_acceptance(self):
        for key,value in (("platform","proxmox"),("mutation_authorized", True),
                          ("windows_guest_qualified", True),("winbot_guest_qualified", True)):
            p=copy.deepcopy(self.plan)
            p[key]=value
            with self.subTest(key=key), self.assertRaises(DomainRenderRefused):
                render_w1_libvirt_xml(p)

    def test_refuses_wrong_owner_media_storage_or_serial(self):
        mutations=(
            ("resource_owner","root", "/var/lib/libvirt/images"),
            ("resource_owner","network", "default"),
            ("resource_owner","not_preexisting", False),
            ("vm_create","machine", "pc-i440fx"),
            ("vm_create","cpu", "qemu64"),
            ("vm_create","enrolled_keys", False),
            ("vm_create","tpm_backend", "none"),
        )
        for parent,key,value in mutations:
            p=copy.deepcopy(self.plan)
            p[parent][key]=value
            with self.subTest(key=key), self.assertRaises(DomainRenderRefused):
                render_w1_libvirt_xml(p)
        mutations=(
            ("storage","path", "/dev/sda"),
            ("storage","bus", "virtio"),
            ("storage","size_gib", 128),
            ("installer_cdrom","path", "/home/runner/Windows.iso"),
            ("installer_cdrom","readonly", False),
            ("seed_cdrom","readonly", False),
            ("network","binding", "default"),
            ("network","model", "virtio"),
            ("serial","path", "/var/log/serial.log"),
        )
        for parent,key,value in mutations:
            p=copy.deepcopy(self.plan)
            p["vm_create"][parent][key]=value
            with self.subTest(parent=parent,key=key), self.assertRaises(DomainRenderRefused):
                render_w1_libvirt_xml(p)

    def test_refuses_unknown_cleanup_and_postinstall_guard(self):
        p=copy.deepcopy(self.plan)
        p["cleanup_required"]["tpm_state_absent"]=False
        with self.assertRaises(DomainRenderRefused):
            render_w1_libvirt_xml(p)
        p=copy.deepcopy(self.plan)
        p["post_install_transition"]["system_disk_only_boot"]=False
        with self.assertRaises(DomainRenderRefused):
            render_w1_libvirt_xml(p)

    def test_refuses_firmware_override_or_unqualified_abi(self):
        for key,value in (
            ("ovmf_code", "/tmp/OVMF_CODE.fd"),
            ("ovmf_vars", "/etc/somewhere/VARS.fd"),
        ):
            with self.subTest(key=key), self.assertRaises(DomainRenderRefused):
                render_w1_libvirt_xml(self.plan, **{key:value})
        p=copy.deepcopy(self.plan)
        p["vm_create"]["memory_mib"]=True
        with self.assertRaises(DomainRenderRefused):
            render_w1_libvirt_xml(p)


if __name__ == "__main__":
    unittest.main()
