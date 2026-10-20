#!/usr/bin/env python3
"""Source-only non-destructive Windows PE probe seed for WinBot W1.

Windows PE execution NOT qualified. This does not install Windows, create/clean
partitions, mutate target disks, accept Microsoft license terms, or authorize
unattended installation. Distinct from W1 WillWipeDisk=true seed.
"""
from __future__ import annotations

import hashlib
import json
import re
import xml.etree.ElementTree as ET

from scripts.windows_w1_winpe_disk_identity import diskpart_readonly_commands

U = "urn:schemas-microsoft-com:unattend"
W = "http://schemas.microsoft.com/WMIConfig/2002/State"
NONCE = re.compile(r"^[A-Za-z0-9_-]{16,64}$")
ET.register_namespace("", U)
ET.register_namespace("wcm", W)

class WinPEProbeSeedRefused(ValueError):
    pass

def probe_unattend() -> str:
    """No DiskConfiguration, ImageInstall, disk selection, credentials or keys."""
    root = ET.Element("{"+U+"}unattend")
    settings=ET.SubElement(root,"{"+U+"}settings",{"pass":"windowsPE"})
    setup=ET.SubElement(settings,"{"+U+"}component",{
        "name":"Microsoft-Windows-Setup",
        "processorArchitecture":"amd64","publicKeyToken":"31bf3856ad364e35",
        "language":"neutral","versionScope":"nonSxS",
    })
    ET.SubElement(setup,"{"+U+"}UseConfigurationSet").text="true"
    runs=ET.SubElement(setup,"{"+U+"}RunSynchronous")
    command=ET.SubElement(runs,"{"+U+"}RunSynchronousCommand",
                          {"{"+W+"}action":"add"})
    ET.SubElement(command,"{"+U+"}Order").text="1"
    ET.SubElement(command,"{"+U+"}Description").text="Read-only WinPE disk identity observation; no installation"
    # SOURCE-ONLY proposal: Windows Setup's configuration-set root is the
    # sole seed authority. Never scan all volumes or execute a marker-matched
    # script from an unrelated drive. RunSynchronous expansion of this
    # variable is still UNQUALIFIED inside a real Windows PE guest.
    path='cmd.exe /D /C call "%configsetroot%\\adw1pe.cmd"'
    if len(path)>259:
        raise WinPEProbeSeedRefused("Windows Setup Path limit exceeded")
    ET.SubElement(command,"{"+U+"}Path").text=path
    ET.indent(root, space="  ")
    return '<?xml version="1.0" encoding="utf-8"?>\n'+ET.tostring(root,encoding="unicode")+"\n"

def probe_batch(nonce: str) -> str:
    if not isinstance(nonce,str) or NONCE.fullmatch(nonce) is None:
        raise WinPEProbeSeedRefused("invalid fresh serial nonce")
    # All files written by this batch are in WinPE's RAM-backed %SystemRoot%\Temp.
    # diskpart-readonly.txt is on the run-owned optical seed drive and read-only.
    # Always return nonzero to avoid treating diagnostic completion as install pass.
    return (
        "@echo off\r\n"
        "setlocal EnableExtensions DisableDelayedExpansion\r\n"
        'set "OUT=%SystemRoot%\\Temp\\ad-w1-disk0-observation.txt"\r\n'
        'diskpart /s "%~dp0diskpart-readonly.txt" > "%OUT%" 2>&1\r\n'
        'set "DISKPART_RC=%ERRORLEVEL%"\r\n'
        "mode COM1 BAUD=115200 PARITY=n DATA=8 STOP=1 >nul 2>&1\r\n"
        "if errorlevel 1 exit /b 85\r\n"
        "(\r\n"
        "  echo AD_W1_WINPE_BEGIN="+nonce+"\r\n"
        '  type "%OUT%"\r\n'
        "  echo AD_W1_WINPE_END="+nonce+"\r\n"
        ") > COM1\r\n"
        "if errorlevel 1 exit /b 86\r\n"
        "if not \"%DISKPART_RC%\"==\"0\" exit /b 87\r\n"
        "exit /b 88\r\n"
    )

def build_probe_seed(nonce: str) -> dict[str, object]:
    script=probe_batch(nonce)
    items={
        "Autounattend.xml":probe_unattend(),
        "adw1pe.cmd":script,
        "diskpart-readonly.txt":diskpart_readonly_commands(),
    }
    xml=ET.fromstring(items["Autounattend.xml"])
    for forbidden in ("DiskConfiguration","ImageInstall","InstallTo","ProductKey",
                      "Credentials","UserData"):
        if xml.findall(".//{"+U+"}"+forbidden):
            raise WinPEProbeSeedRefused("unexpected unattended installation element")
    return {
        "schema":"winbot-w1-pe-observer-seed/v1",
        "classification":"SOURCE_ONLY_INERT_OBSERVER",
        "nonce":nonce,
        "files":items,
        "file_sha256":{k:hashlib.sha256(v.encode("utf-8")).hexdigest()
                       for k,v in items.items()},
        "unique_seed_binding":"CONFIGURATION_SET_ROOT_CANDIDATE_UNQUALIFIED",
        "guest_configsetroot_expansion_proved":False,
        "winpe_executed":False,
        "disk_identity_real_guest_observed":False,
        "windows_installation_authorized":False,
        "windows_installed":False,
        "winbot_guest_qualified":False,
    }
