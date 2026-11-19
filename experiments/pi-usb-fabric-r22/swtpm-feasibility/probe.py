#!/usr/bin/env python3
"""QEMU + upstream swtpm TPM2 device-wiring feasibility, NOT guest attestation."""
import json
import os
from pathlib import Path
import socket
import subprocess
import tempfile
import time

def check_alive(p,label):
    if p.poll() is not None:
        out=b"" if p.stderr is None else p.stderr.read()
        raise RuntimeError(label+" exited: "+str(p.returncode)+" "+out.decode(errors="replace")[-300:])

def wait_file(path,proc,label,seconds=12):
    end=time.monotonic()+seconds
    while time.monotonic()<end:
        check_alive(proc,label)
        if path.exists():return
        time.sleep(0.08)
    raise RuntimeError(label+" socket not observed")

def qmp_call(reader,writer,command):
    writer.write((json.dumps({"execute":command})+"\n").encode())
    writer.flush()
    for _ in range(100):
        line=reader.readline()
        if not line:raise RuntimeError("QMP closed on "+command)
        msg=json.loads(line)
        if "event" in msg:continue
        if "error" in msg:raise RuntimeError("QMP "+command+" failed "+str(msg["error"]))
        if "return" not in msg:raise RuntimeError("QMP lacked return "+command)
        return msg["return"]
    raise RuntimeError("QMP event flood")

def qemu_command(control,qmp):
    return [
        "qemu-system-x86_64","-machine","q35,accel=tcg",
        "-m","256","-smp","1","-S","-nodefaults",
        "-display","none","-monitor","none","-serial","none",
        "-net","none","-no-reboot",
        "-chardev","socket,id=chrtpm,path="+str(control),
        "-tpmdev","emulator,id=tpm0,chardev=chrtpm",
        "-device","tpm-tis,tpmdev=tpm0",
        "-qmp","unix:"+str(qmp)+",server=on,wait=off",
    ]

def main():
    with tempfile.TemporaryDirectory(prefix="r22-swtpm-",dir="/tmp") as tmp:
        root=Path(tmp)
        state=root/"state"
        state.mkdir(mode=0o700)
        control=root/"swtpm.sock"
        qmp=root/"qmp.sock"
        proc=None
        qemu=None
        try:
            proc=subprocess.Popen([
                "swtpm","socket","--tpmstate","dir="+str(state),
                "--ctrl","type=unixio,path="+str(control),
                "--tpm2","--log","level=2",
            ],stdout=subprocess.DEVNULL,stderr=subprocess.PIPE)
            wait_file(control,proc,"swtpm TPM2")
            print("R22_C_SOFTWARE_TPM2_CONTROL_SOCKET_READY=PASS",flush=True)
            qemu=subprocess.Popen(qemu_command(control,qmp),
                stdout=subprocess.DEVNULL,stderr=subprocess.PIPE)
            wait_file(qmp,qemu,"QEMU QMP",15)
            with socket.socket(socket.AF_UNIX,socket.SOCK_STREAM) as conn:
                conn.settimeout(8)
                conn.connect(str(qmp))
                reader=conn.makefile("rb",buffering=0)
                writer=conn.makefile("wb",buffering=0)
                greeting=json.loads(reader.readline())
                if "QMP" not in greeting:raise RuntimeError("no actual QMP greeting")
                qmp_call(reader,writer,"qmp_capabilities")
                dev=qmp_call(reader,writer,"query-tpm")
                if not isinstance(dev,list) or len(dev)!=1:
                    raise RuntimeError("expected exactly one TPM device: "+repr(dev))
                item=dev[0]
                if item.get("id")!="tpm0" or item.get("model")!="tpm-tis" or (
                    item.get("options") or {}).get("type")!="emulator":
                    raise RuntimeError("wrong QEMU TPM backend: "+repr(item))
                types=qmp_call(reader,writer,"query-tpm-types")
                if "emulator" not in types:raise RuntimeError("emulator backend unsupported")
                print("R22_C_REAL_QEMU_QMP_TPM2_EMULATOR_TIS_OBSERVED=PASS",flush=True)
                print("R22_C_QMP_TPM_TYPES_AND_BACKEND_PRESENT=PASS",flush=True)
            # Negative: a socket which cannot be opened MUST NOT count as
            # a guest TPM. QEMU should refuse the device and exit nonzero.
            fake=root/"missing-tpm.sock"
            bad=qemu_command(fake,root/"negative-qmp.sock")
            denied=subprocess.run(bad,stdout=subprocess.DEVNULL,
                stderr=subprocess.PIPE,timeout=12)
            if denied.returncode==0:
                raise RuntimeError("QEMU admitted missing swtpm backend")
            print("R22_C_MISSING_SWTMP_BACKEND_FAIL_CLOSED=PASS",flush=True)
            print("R22_C_IN_GUEST_TPM_COMMANDS_AND_QUOTE=NOT_TESTED",flush=True)
            print("R22_C_PROTECTED_HARDWARE_ROOT_GUEST_ATTESTATION=NOT_TESTED",flush=True)
        finally:
            for item in (qemu,proc):
                if item is not None and item.poll() is None:
                    item.terminate()
                    try:item.wait(timeout=5)
                    except subprocess.TimeoutExpired:
                        item.kill();item.wait(timeout=5)
            print("R22_C_ALL_DISPOSABLE_QEMU_TPM_PROCESSES_STOPPED=PASS",flush=True)
if __name__=="__main__":main()
