#!/usr/bin/env python3
"""Real Linux guest TPM2 commands via upstream swtpm/QEMU, test only."""
import json
import os
from pathlib import Path
import socket
import subprocess
import tempfile
import time

REQUIRED=(
 "R24_C_REAL_LINUX_GUEST_PID1=PASS",
 "R24_C_GUEST_TPM_TIS_CHARACTER_DEVICE=PASS",
 "R24_C_REAL_GUEST_TPM_GETRANDOM=PASS",
 "R24_C_REAL_GUEST_TPM_PCR_READ=PASS",
 "R24_C_REAL_GUEST_TPM_NONCE_QUOTE_VERIFIED=PASS",
 "R24_C_GUEST_TPM_WRONG_NONCE_DENIED=PASS",
 "R24_C_REAL_GUEST_CHANGED_PCR_QUOTE_DENIED=PASS",
 "R24_C_REAL_QEMU_GUEST_SWTMP_TPM2_COMMANDS=PASS",
 "R24_C_SOFTWARE_TPM_HOST_CONTROLS_IDENTITY=NOT_TESTED",
)

def ready(path,proc,label,timeout=15):
    deadline=time.monotonic()+timeout
    while time.monotonic()<deadline:
        if proc.poll() is not None:
            stderr=b""
            if proc.stdout is not None:
                stderr=proc.stdout.read(65536)
            elif proc.stderr is not None:
                stderr=proc.stderr.read(65536)
            raise RuntimeError(label+" process died: "+str(proc.returncode)+
                " output-tail="+stderr.decode(errors="replace")[-4000:])
        if path.exists():return
        time.sleep(.1)
    raise RuntimeError(label+" socket missing")

def qmp(cmd,channel):
    channel.write((json.dumps({"execute":cmd})+"\n").encode())
    channel.flush()
    while True:
        line=channel.readline()
        if not line:raise RuntimeError("QMP closed on "+cmd)
        event=json.loads(line)
        if "event" in event:continue
        if "error" in event:raise RuntimeError("QMP "+cmd+" error "+repr(event["error"]))
        return event.get("return")

def main():
    with tempfile.TemporaryDirectory(prefix="r24-tpm-guest-",dir="/tmp") as tmp:
        root=Path(tmp)
        state=root/"state"
        state.mkdir(mode=0o700)
        data=root/"swtpm.sock"
        ctrl=root/"swtpm.sock.ctrl"
        qmpSocket=root/"qmp.sock"
        tpm=qemu=None
        try:
            tpm=subprocess.Popen([
                "swtpm","socket","--tpm2","--tpmstate","dir="+str(state),
                "--ctrl","type=unixio,path="+str(ctrl),
                "--server","type=unixio,path="+str(data),
                "--flags","not-need-init,startup-clear",
            ],stdout=subprocess.DEVNULL,stderr=subprocess.PIPE)
            ready(data,tpm,"swtpm")
            ready(ctrl,tpm,"swtpm control")
            print("R24_C_UPSTREAM_SOFTWARE_TPM2_DUAL_SOCKETS=PASS",flush=True)
            qemu=subprocess.Popen([
                "qemu-system-x86_64","-machine","q35,accel=tcg",
                "-m","768","-smp","1","-kernel","/guest/kernel",
                "-initrd","/guest/initrd.gz","-append",
                "console=ttyS0 rdinit=/init panic=1 loglevel=5",
                "-nodefaults","-display","none","-serial","stdio",
                "-monitor","none","-net","none","-no-reboot",
                "-chardev","socket,id=chrtpm,path="+str(ctrl),
                "-tpmdev","emulator,id=tpm0,chardev=chrtpm",
                "-device","tpm-tis,tpmdev=tpm0",
                "-qmp","unix:"+str(qmpSocket)+",server=on,wait=off",
            ],stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT)
            ready(qmpSocket,qemu,"QEMU QMP")
            with socket.socket(socket.AF_UNIX,socket.SOCK_STREAM) as conn:
                conn.settimeout(30)
                conn.connect(str(qmpSocket))
                channel=conn.makefile("rwb",buffering=0)
                greeting=json.loads(channel.readline())
                if "QMP" not in greeting:raise RuntimeError("QMP greeting absent")
                qmp("qmp_capabilities",channel)
                dev=qmp("query-tpm",channel)
                if not isinstance(dev,list) or len(dev)!=1 or (
                    dev[0].get("model")!="tpm-tis" or
                    (dev[0].get("options") or {}).get("type")!="emulator"):
                    raise RuntimeError("real QEMU TPM TIS was absent")
                print("R24_C_SAME_QEMU_TPM_TIS_QMP_OBSERVED=PASS",flush=True)
            try:
                output,_=qemu.communicate(timeout=115)
            except subprocess.TimeoutExpired:
                qemu.kill()
                output,_=qemu.communicate(timeout=10)
                raise RuntimeError("guest TPM boot/quote timed out, kernel tail="+
                    output.decode(errors="replace")[-8000:])
            trace=output.decode(errors="replace")
            print("R24_C_GUEST_KERNEL_SERIAL_TAIL_START",flush=True)
            print(trace[-12000:],flush=True)
            print("R24_C_GUEST_KERNEL_SERIAL_TAIL_END",flush=True)
            missing=[m for m in REQUIRED if m not in trace]
            if missing:raise RuntimeError("guest TPM evidence missing "+repr(missing))
            if "R24_C_GUEST_TPM_TIS_CHARACTER_DEVICE=RED" in trace or (
                "R24_C_REAL_GUEST_TPM_GETRANDOM=RED" in trace):
                raise RuntimeError("guest TPM early failure observed")
            if qemu.returncode!=0:
                raise RuntimeError("QEMU exited nonzero "+repr(qemu.returncode))
            print("R24_C_REAL_IN_GUEST_TPM2_PCR_QUOTE_TEST_ONLY=PASS",flush=True)
            print("R24_C_TRUSTED_HARDWARE_EK_ATTESTATION=NOT_TESTED",flush=True)
        finally:
            for proc in (qemu,tpm):
                if proc is not None and proc.poll() is None:
                    proc.terminate()
                    try:proc.wait(timeout=5)
                    except subprocess.TimeoutExpired:proc.kill();proc.wait(timeout=5)
            print("R24_C_ALL_DISPOSABLE_QEMU_SWTMP_PROCESSES_STOPPED=PASS",flush=True)

if __name__=="__main__": main()
