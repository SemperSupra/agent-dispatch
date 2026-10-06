#!/usr/bin/env python3
from __future__ import annotations

import argparse
import hashlib
import json
import pathlib
import re
import xml.etree.ElementTree as ET

NONCE_RE = re.compile(r"^[A-Za-z0-9_-]{16,64}$")
IMAGE_RE = re.compile(r"^[^\r\n\x00]{1,128}$")
SEED_LABEL = "ADW1SEED"
MARKER_PREFIX = "AGENT_DISPATCH_W1_NONCE="

UNATTEND_NS = "urn:schemas-microsoft-com:unattend"
WCM_NS = "http://schemas.microsoft.com/WMIConfig/2002/State"

ET.register_namespace("", UNATTEND_NS)
ET.register_namespace("wcm", WCM_NS)


class WindowsW1SeedError(RuntimeError):
    pass


def _validate(value: str, pattern: re.Pattern[str], label: str) -> str:
    if not isinstance(value, str) or not pattern.fullmatch(value):
        raise WindowsW1SeedError(f"{label} violates Windows W1 seed contract")
    return value


def _component(parent: ET.Element, name: str, pass_name: str) -> ET.Element:
    settings = ET.SubElement(parent, f"{{{UNATTEND_NS}}}settings", {"pass": pass_name})
    return ET.SubElement(
        settings,
        f"{{{UNATTEND_NS}}}component",
        {
            "name": name,
            "processorArchitecture": "amd64",
            "publicKeyToken": "31bf3856ad364e35",
            "language": "neutral",
            "versionScope": "nonSxS",
        },
    )


def _add(parent: ET.Element, name: str, text: str | int | bool | None = None, **attrs: str) -> ET.Element:
    node = ET.SubElement(parent, f"{{{UNATTEND_NS}}}{name}", attrs)
    if text is not None:
        if isinstance(text, bool):
            node.text = "true" if text else "false"
        else:
            node.text = str(text)
    return node


def bootstrap_script(nonce: str) -> str:
    nonce = _validate(nonce, NONCE_RE, "nonce")
    marker = MARKER_PREFIX + nonce
    return f"""$ErrorActionPreference = 'Stop'
$root = Join-Path $env:ProgramData 'AgentDispatch'
$emit = Join-Path $root 'emit-w1-nonce.ps1'
New-Item -ItemType Directory -Force -Path $root | Out-Null

$payload = @'
$ErrorActionPreference = 'Stop'
$marker = '{marker}'
for ($i = 0; $i -lt 30; $i++) {{
    try {{
        $port = [System.IO.Ports.SerialPort]::new('COM1', 115200, 'None', 8, 'One')
        $port.NewLine = [Environment]::NewLine
        $port.Open()
        $port.WriteLine($marker)
        $port.Close()
        exit 0
    }} catch {{
        Start-Sleep -Seconds 2
    }}
}}
exit 2
'@

Set-Content -LiteralPath $emit -Value $payload -Encoding UTF8

$action = New-ScheduledTaskAction -Execute 'powershell.exe' -Argument ('-NoProfile -ExecutionPolicy Bypass -File "' + $emit + '"')
$trigger = New-ScheduledTaskTrigger -AtStartup
Register-ScheduledTask -TaskName 'AgentDispatchW1Nonce' -Action $action -Trigger $trigger -User 'SYSTEM' -RunLevel Highest -Force | Out-Null
& $emit
"""


def build_unattend(image_name: str) -> str:
    image_name = _validate(image_name, IMAGE_RE, "image-name")
    root = ET.Element(f"{{{UNATTEND_NS}}}unattend")

    intl = _component(root, "Microsoft-Windows-International-Core-WinPE", "windowsPE")
    for key in ("SetupUILanguage",):
        sub = _add(intl, key)
        _add(sub, "UILanguage", "en-US")
    for key in ("InputLocale", "SystemLocale", "UILanguage", "UserLocale"):
        _add(intl, key, "en-US")

    setup = _component(root, "Microsoft-Windows-Setup", "windowsPE")
    disk_config = _add(setup, "DiskConfiguration")
    disk = _add(disk_config, "Disk", **{f"{{{WCM_NS}}}action": "add"})
    _add(disk, "DiskID", 0)
    _add(disk, "WillWipeDisk", True)

    creates = _add(disk, "CreatePartitions")
    for order, kind, size, extend in (
        (1, "EFI", 260, False),
        (2, "MSR", 16, False),
        (3, "Primary", None, True),
    ):
        cp = _add(creates, "CreatePartition", **{f"{{{WCM_NS}}}action": "add"})
        _add(cp, "Order", order)
        _add(cp, "Type", kind)
        if size is not None:
            _add(cp, "Size", size)
        if extend:
            _add(cp, "Extend", True)

    modifies = _add(disk, "ModifyPartitions")
    mp1 = _add(modifies, "ModifyPartition", **{f"{{{WCM_NS}}}action": "add"})
    _add(mp1, "Order", 1)
    _add(mp1, "PartitionID", 1)
    _add(mp1, "Format", "FAT32")
    _add(mp1, "Label", "SYSTEM")

    mp3 = _add(modifies, "ModifyPartition", **{f"{{{WCM_NS}}}action": "add"})
    _add(mp3, "Order", 2)
    _add(mp3, "PartitionID", 3)
    _add(mp3, "Format", "NTFS")
    _add(mp3, "Label", "Windows")
    _add(mp3, "Letter", "C")

    image_install = _add(setup, "ImageInstall")
    os_image = _add(image_install, "OSImage")
    install_from = _add(os_image, "InstallFrom")
    metadata = _add(install_from, "MetaData", **{f"{{{WCM_NS}}}action": "add"})
    _add(metadata, "Key", "/IMAGE/NAME")
    _add(metadata, "Value", image_name)
    install_to = _add(os_image, "InstallTo")
    _add(install_to, "DiskID", 0)
    _add(install_to, "PartitionID", 3)

    user_data = _add(setup, "UserData")
    _add(user_data, "AcceptEula", True)

    deploy = _component(root, "Microsoft-Windows-Deployment", "specialize")
    sync = _add(deploy, "RunSynchronous")
    cmd = _add(sync, "RunSynchronousCommand", **{f"{{{WCM_NS}}}action": "add"})
    _add(cmd, "Order", 1)
    _add(cmd, "Description", "Install Agent Dispatch W1 serial readiness oracle")
    command = (
        "powershell.exe -NoProfile -ExecutionPolicy Bypass -Command "
        "\"$v=Get-Volume -FileSystemLabel 'ADW1SEED' -ErrorAction Stop; "
        "$p=($v.DriveLetter + ':\\\\w1-bootstrap.ps1'); & $p\""
    )
    if len(command) > 259:
        raise WindowsW1SeedError("specialize bootstrap command exceeds Windows unattend Path bound")
    _add(cmd, "Path", command)
    _add(cmd, "WillReboot", "Never")

    shell = _component(root, "Microsoft-Windows-Shell-Setup", "oobeSystem")
    oobe = _add(shell, "OOBE")
    _add(oobe, "HideEULAPage", True)
    _add(oobe, "HideWirelessSetupInOOBE", True)
    _add(oobe, "ProtectYourPC", 3)

    ET.indent(root, space="  ")
    return '<?xml version="1.0" encoding="utf-8"?>\n' + ET.tostring(root, encoding="unicode") + "\n"


def sha256_text(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def write_seed(out_dir: pathlib.Path, nonce: str, image_name: str) -> dict[str, object]:
    nonce = _validate(nonce, NONCE_RE, "nonce")
    xml = build_unattend(image_name)
    ps1 = bootstrap_script(nonce)
    out_dir.mkdir(parents=True, exist_ok=True)
    (out_dir / "Autounattend.xml").write_text(xml, encoding="utf-8")
    (out_dir / "w1-bootstrap.ps1").write_text(ps1, encoding="utf-8")
    receipt = {
        "schema": "windows-w1-unattend-seed/v1",
        "classification": "SUPPORTED",
        "oracleSatisfied": True,
        "seed_volume_label": SEED_LABEL,
        "image_name": image_name,
        "nonce_marker": MARKER_PREFIX + nonce,
        "observer_contract": {
            "transport": "serial-com1",
            "baud": 115200,
            "required_marker": MARKER_PREFIX + nonce,
            "first_observation": "specialize",
            "restart_observation": "scheduled-task-at-startup",
        },
        "files": {
            "Autounattend.xml": sha256_text(xml),
            "w1-bootstrap.ps1": sha256_text(ps1),
        },
        "security": {
            "embedded_product_key": False,
            "embedded_password": False,
            "network_dependency": False,
            "guest_agent_dependency": False,
        },
        "claim_boundary": (
            "source-only deterministic unattended/readiness seed; platform serial-device "
            "binding and Windows runtime acceptance remain separate"
        ),
    }
    (out_dir / "seed-contract.json").write_text(
        json.dumps(receipt, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    return receipt


def main() -> int:
    p = argparse.ArgumentParser()
    p.add_argument("--nonce", required=True)
    p.add_argument("--image-name", required=True)
    p.add_argument("--out-dir", type=pathlib.Path, required=True)
    a = p.parse_args()
    try:
        receipt = write_seed(a.out_dir, a.nonce, a.image_name)
    except (OSError, WindowsW1SeedError) as exc:
        print(json.dumps({
            "schema": "windows-w1-unattend-seed/v1",
            "classification": "PLAN_FAILURE",
            "oracleSatisfied": False,
            "detail": f"{type(exc).__name__}: {exc}",
        }, sort_keys=True))
        return 2
    print(json.dumps(receipt, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
