#!/usr/bin/env python3
"""Source-only lowering of the admitted-*plan* Windows W1 intent to libvirt XML.

Authority: mark-e-deyoung/WinBot#108; public W1 plan PR #508.
No VM create, source-media download, network mutation, unattended disk wipe,
Windows product qualification, WinBot guest deployment, or Apply admission.
"""
from __future__ import annotations

from pathlib import PurePosixPath
import uuid
import xml.etree.ElementTree as ET
from typing import Any, Mapping

class DomainRenderRefused(ValueError):
    pass

def require(condition: bool, reason: str) -> None:
    if not condition:
        raise DomainRenderRefused(reason)

def render_w1_libvirt_xml(
    plan: Mapping[str, Any],
    *,
    ovmf_code: str = "/usr/share/OVMF/OVMF_CODE_4M.secboot.fd",
    ovmf_vars: str = "/usr/share/OVMF/OVMF_VARS_4M.ms.fd",
) -> str:
    """Render an inert XML proposal. Caller MUST reobserve/revalidate before Apply."""
    require(plan.get("schema") == "windows-w1-native-plan/v1", "wrong W1 plan schema")
    require(plan.get("platform") == "libvirt-kvm", "wrong product provider")
    require(plan.get("mutation_authorized") is False, "unexpected mutable/admitted plan")
    require(plan.get("windows_guest_qualified") is False and
            plan.get("winbot_guest_qualified") is False, "guest acceptance incorrectly claimed")
    owner = plan.get("resource_owner")
    vm = plan.get("vm_create")
    require(isinstance(owner, Mapping) and isinstance(vm, Mapping), "missing owner or VM intent")
    raw_uuid = owner.get("uuid")
    try:
        ident = uuid.UUID(raw_uuid)
    except (ValueError, TypeError, AttributeError) as exc:
        raise DomainRenderRefused("invalid UUID") from exc
    require(ident.version == 4 and str(ident) == raw_uuid, "UUID must be exact canonical v4")
    root = "/var/lib/libvirt/images/ad-w1-" + ident.hex
    net = "ad-w1-" + ident.hex
    require(owner.get("root") == root and owner.get("network") == net and
            owner.get("not_preexisting") is True, "unowned or preexisting resource")
    require(vm.get("domain_type") == "kvm" and vm.get("machine") == "q35" and
            vm.get("cpu") == "host-passthrough", "unsafe KVM/CPU configuration")
    require(vm.get("firmware") == "UEFI" and vm.get("secure_boot") is True and
            vm.get("enrolled_keys") is True and vm.get("tpm_backend") == "swtpm-emulator-v2",
            "missing observed SecureBoot/TPM2 intent")
    require(ovmf_code == "/usr/share/OVMF/OVMF_CODE_4M.secboot.fd" and
            ovmf_vars == "/usr/share/OVMF/OVMF_VARS_4M.ms.fd",
            "firmware path/profile not qualified in cheap host evidence")
    require(type(vm.get("vcpus")) is int and vm["vcpus"] == 2 and
            type(vm.get("memory_mib")) is int and vm["memory_mib"] == 4096,
            "VM resource shape mismatch")
    disk = vm.get("storage")
    iso = vm.get("installer_cdrom")
    seed = vm.get("seed_cdrom")
    network = vm.get("network")
    serial = vm.get("serial")
    require(all(isinstance(x, Mapping) for x in (disk, iso, seed, network, serial)),
            "missing explicit storage/network/serial intent")
    expected = (
        root + "/system.qcow2",
        root + "/windows11-install.iso",
        root + "/unattended-seed.iso",
        root + "/serial.log",
    )
    require((disk.get("path"), iso.get("path"), seed.get("path"), serial.get("path")) == expected,
            "resource paths not exactly run-owned")
    require(disk.get("role") == "single-run-owned-blank-writable-system" and
            disk.get("driver") == "qcow2" and disk.get("bus") == "sata" and
            disk.get("size_gib") == 64, "system disk is not the single run-owned SATA fixture")
    require(iso.get("readonly") is True and seed.get("readonly") is True and
            iso.get("boot_priority") == 1 and seed.get("volume_label") == "ADW1SEED",
            "installer/seed media configuration mismatch")
    require(network.get("binding") == net and network.get("model") == "e1000" and
            network.get("type") == "owned-isolated-network", "network must be run-owned")
    require(serial.get("device") == "COM1" and
            serial.get("oracle") == "AGENT_DISPATCH_W1_NONCE=",
            "external guest readiness channel missing")
    require(plan.get("cleanup_required") and
            all(v is True for v in plan["cleanup_required"].values()), "cleanup incomplete")
    require(plan.get("post_install_transition", {}).get("system_disk_only_boot") is True,
            "required system-only restart not requested")
    for p in expected:
        require(str(PurePosixPath(p)) == p and
                PurePosixPath(p).is_relative_to(PurePosixPath(root)),
                "noncanonical/unowned path")

    domain = ET.Element("domain", {"type": "kvm"})
    ET.SubElement(domain, "name").text = net
    ET.SubElement(domain, "uuid").text = raw_uuid
    ET.SubElement(domain, "memory", {"unit": "MiB"}).text = str(vm["memory_mib"])
    ET.SubElement(domain, "vcpu").text = str(vm["vcpus"])
    os_el = ET.SubElement(domain, "os")
    ET.SubElement(os_el, "type", {"arch": "x86_64", "machine": "q35"}).text = "hvm"
    ET.SubElement(os_el, "loader", {"readonly": "yes", "type": "pflash", "secure": "yes"}).text = ovmf_code
    ET.SubElement(os_el, "nvram", {"template": ovmf_vars}).text = root + "/nvram.fd"
    features = ET.SubElement(domain, "features")
    ET.SubElement(features, "acpi")
    ET.SubElement(features, "smm", {"state": "on"})
    ET.SubElement(domain, "cpu", {"mode": "host-passthrough"})
    devices = ET.SubElement(domain, "devices")
    ET.SubElement(devices, "emulator").text = "/usr/bin/qemu-system-x86_64"

    # Exactly ONE writable disk. The unattended installer may target only it.
    sysdisk = ET.SubElement(devices, "disk", {"type": "file", "device": "disk"})
    ET.SubElement(sysdisk, "driver", {"name": "qemu", "type": "qcow2"})
    ET.SubElement(sysdisk, "source", {"file": expected[0]})
    ET.SubElement(sysdisk, "target", {"dev": "sda", "bus": "sata"})
    ET.SubElement(sysdisk, "boot", {"order": "2"})
    for path, target, boot in ((expected[1], "sdb", True), (expected[2], "sdc", False)):
        optical = ET.SubElement(devices, "disk", {"type": "file", "device": "cdrom"})
        ET.SubElement(optical, "driver", {"name": "qemu", "type": "raw"})
        ET.SubElement(optical, "source", {"file": path})
        ET.SubElement(optical, "target", {"dev": target, "bus": "sata"})
        ET.SubElement(optical, "readonly")
        if boot:
            ET.SubElement(optical, "boot", {"order": "1"})
    iface = ET.SubElement(devices, "interface", {"type": "network"})
    ET.SubElement(iface, "source", {"network": net})
    ET.SubElement(iface, "model", {"type": "e1000"})
    tpm = ET.SubElement(devices, "tpm", {"model": "tpm-tis"})
    ET.SubElement(tpm, "backend", {"type": "emulator", "version": "2.0"})
    output = ET.SubElement(devices, "serial", {"type": "file"})
    ET.SubElement(output, "source", {"path": expected[3]})
    ET.SubElement(output, "target", {"port": "0"})
    # Loopback-only viewer, not an exposed guest-control endpoint.
    graphics = ET.SubElement(devices, "graphics", {"type": "vnc", "autoport": "yes", "listen": "127.0.0.1"})
    ET.SubElement(graphics, "listen", {"type": "address", "address": "127.0.0.1"})
    return ET.tostring(domain, encoding="unicode") + "\n"
