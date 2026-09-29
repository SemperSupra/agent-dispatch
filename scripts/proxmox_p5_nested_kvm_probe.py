#!/usr/bin/env python3
"""Prepared Proxmox P5 oracle: actual L3 KVM vCPU nonce execution.

Preparation only. P5 is not satisfied by /dev/kvm, vmx/svm, or a successful
QEMU process launch. A nested vCPU must execute our boot sector and emit the
nonce through the debug I/O port while QEMU is forced to use KVM acceleration.
"""
from __future__ import annotations

import argparse
import json
import pathlib
import subprocess

SCHEMA = "proxmox-p5-nested-kvm/v1"
EXPECTED_DEBUG_EXIT_RC = 85


def boot_sector(nonce: str) -> bytes:
    message = (nonce + "\n").encode("ascii") + b"\x00"
    # 16-bit real mode, loaded by BIOS at 0000:7c00:
    # DS=0; CLD; DX=0xe9; SI=message; stream NUL-terminated bytes to debugcon;
    # then write 0x2a to isa-debug-exit at 0xf4 and halt.
    code = bytes.fromhex(
        "31c0"      # xor ax,ax
        "8ed8"      # mov ds,ax
        "fc"        # cld
        "bae900"    # mov dx,0x00e9
        "be1a7c"    # mov si,0x7c1a (message starts at byte 26)
        "ac"        # lodsb
        "84c0"      # test al,al
        "7403"      # jz exit
        "ee"        # out dx,al
        "ebf8"      # jmp loop
        "baf400"    # exit: mov dx,0x00f4
        "b02a"      # mov al,0x2a
        "ee"        # out dx,al
        "f4"        # hlt
    )
    if len(code) != 26:
        raise AssertionError(len(code))
    payload = code + message
    if len(payload) > 510:
        raise ValueError("nonce too long")
    return payload + b"\x00" * (510 - len(payload)) + b"\x55\xaa"


REMOTE = r'''import json, os, pathlib, secrets, shutil, subprocess, tempfile
SCHEMA="proxmox-p5-nested-kvm/v1"
EXPECTED_DEBUG_EXIT_RC=85

def boot_sector(nonce):
    message=(nonce+"\n").encode("ascii")+b"\x00"
    code=bytes.fromhex("31c08ed8fcbae900be1a7cac84c07403eeebf8baf400b02aeef4")
    return code+message+b"\x00"*(510-len(code)-len(message))+b"\x55\xaa"

out={"schema":SCHEMA,"classification":"ORACLE_FAILURE","oracleSatisfied":False}
try:
    qemu=shutil.which("qemu-system-x86_64") or shutil.which("kvm")
    if not qemu:
        raise RuntimeError("nested QEMU executable absent")
    out["qemu_binary"]=qemu
    out["qemu_version"]=subprocess.run([qemu,"--version"],text=True,capture_output=True,timeout=20).stdout.splitlines()[:2]
    out["kvm_device"]=pathlib.Path("/dev/kvm").exists()
    cpuinfo=pathlib.Path("/proc/cpuinfo").read_text(errors="replace")
    out["cpu_virtualization_flag"]=(" vmx " in (" "+cpuinfo.replace("\n"," ")+" ") or " svm " in (" "+cpuinfo.replace("\n"," ")+" "))
    if not out["kvm_device"]:
        raise RuntimeError("/dev/kvm absent inside Proxmox guest")

    nonce="P5-NONCE-"+secrets.token_hex(12)
    out["nonce"]=nonce
    with tempfile.TemporaryDirectory(prefix="pve-rdte-p5-") as td:
        image=pathlib.Path(td)/"nonce-boot.bin"
        image.write_bytes(boot_sector(nonce))
        cp=subprocess.run([
            qemu,
            "-accel","kvm",
            "-cpu","host",
            "-m","64",
            "-display","none",
            "-monitor","none",
            "-serial","none",
            "-boot","order=a,strict=on",
            "-drive",f"file={image},format=raw,if=floppy,readonly=on",
            "-chardev","stdio,id=debug,signal=off",
            "-device","isa-debugcon,iobase=0xe9,chardev=debug",
            "-device","isa-debug-exit,iobase=0xf4,iosize=0x04",
            "-no-reboot",
        ],text=True,capture_output=True,timeout=30)
        out["qemu_rc"]=cp.returncode
        out["debug_stdout"]=cp.stdout[-4000:]
        out["qemu_stderr"]=cp.stderr[-8000:]
        if cp.returncode != EXPECTED_DEBUG_EXIT_RC:
            raise RuntimeError(f"nested QEMU did not return debug-exit rc {EXPECTED_DEBUG_EXIT_RC}")
        if nonce not in cp.stdout:
            raise RuntimeError("nested vCPU did not execute and emit the nonce")
    out["classification"]="SUPPORTED"
    out["oracleSatisfied"]=True
    out["detail"]="L3 x86 boot sector executed under forced KVM acceleration and emitted the exact nonce"
except Exception as exc:
    out["detail"]=f"{type(exc).__name__}: {exc}"
print(json.dumps(out,sort_keys=True))
'''


def run_remote(host: str, port: int, password_file: pathlib.Path, timeout: int = 120):
    argv=[
        "sshpass","-f",str(password_file),
        "ssh","-p",str(port),
        "-o","StrictHostKeyChecking=no",
        "-o","UserKnownHostsFile=/dev/null",
        "-o","ConnectTimeout=8",
        f"root@{host}","python3","-",
    ]
    cp=subprocess.run(argv,input=REMOTE,text=True,capture_output=True,timeout=timeout)
    if cp.returncode != 0:
        return {
            "schema":SCHEMA,
            "classification":"ORACLE_FAILURE",
            "oracleSatisfied":False,
            "detail":f"SSH/remote P5 driver failed rc={cp.returncode}",
            "ssh_stderr":cp.stderr[-12000:],
        }
    try:
        return json.loads(cp.stdout.strip().splitlines()[-1])
    except Exception as exc:
        return {
            "schema":SCHEMA,
            "classification":"ORACLE_FAILURE",
            "oracleSatisfied":False,
            "detail":f"remote P5 output was not JSON: {type(exc).__name__}",
            "ssh_stderr":cp.stderr[-12000:],
            "remote_stdout_tail":cp.stdout[-12000:],
        }


def main() -> int:
    ap=argparse.ArgumentParser()
    ap.add_argument("--host",default="127.0.0.1")
    ap.add_argument("--port",type=int,required=True)
    ap.add_argument("--password-file",type=pathlib.Path,required=True)
    ap.add_argument("--out",type=pathlib.Path,required=True)
    args=ap.parse_args()
    payload=run_remote(args.host,args.port,args.password_file)
    args.out.write_text(json.dumps(payload,indent=2,sort_keys=True)+"\n",encoding="utf-8")
    print(json.dumps({
        "classification":payload.get("classification"),
        "oracleSatisfied":payload.get("oracleSatisfied"),
        "nonce_executed":bool(payload.get("nonce") and payload.get("nonce") in str(payload.get("debug_stdout",""))),
    },sort_keys=True))
    return 0


if __name__=="__main__":
    raise SystemExit(main())
