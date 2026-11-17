#!/usr/bin/env python3
"""R26-L5 live negative oracle: missing journal must not admit a stale QEMU guest.

Only disposable QEMU TCG Linux guest, synthetic USB key A and tmpfs journal.
The historical fail-open is expected to make THIS oracle fail CI (RED).
"""
import json
import os
from pathlib import Path
import select
import subprocess
import tempfile
import time

def ready(proc, marker, timeout=20):
    until=time.monotonic()+timeout
    while time.monotonic()<until:
        if proc.poll() is not None:
            out=(proc.stdout.read() if proc.stdout else "")
            err=(proc.stderr.read() if proc.stderr else "")
            return False,out+err
        available,_,_=select.select([proc.stdout],[],[],0.15)
        if available:
            line=proc.stdout.readline()
            if marker in line:
                return True,line
    return False,"timeout waiting for "+marker

def request(frontend,payload):
    frontend.stdin.write(json.dumps(payload)+"\n")
    frontend.stdin.flush()
    available,_,_=select.select([frontend.stdout],[],[],15)
    if not available:
        raise RuntimeError("frontend request timeout")
    line=frontend.stdout.readline()
    if not line:
        raise RuntimeError("frontend disconnected")
    return json.loads(line)

def stop(p):
    if p is not None and p.poll() is None:
        p.kill()
        p.wait(timeout=5)

def main():
    with tempfile.TemporaryDirectory(prefix="r26-l5-",dir="/tmp") as d:
        root=Path(d)
        media=root/"synthetic.img"
        media.write_bytes(b"R26-L5-SYNTHETIC" + bytes(2097152-16))
        journal=root/"held.json"
        qmp=str(root/"qmp.sock")
        socket=str(root/"actuator.sock")
        socket2=str(root/"actuator-restarted.sock")
        qemu=subprocess.Popen([
            "qemu-system-x86_64","-machine","q35","-accel","tcg",
            "-cpu","qemu64","-m","1024M","-smp","1","-S",
            "-nodefaults","-display","none","-monitor","none",
            "-serial","stdio","-net","none","-no-reboot",
            "-kernel","/guest/kernel","-initrd","/guest/initrd.gz",
            "-append","console=ttyS0 rdinit=/init loglevel=7 panic=-1",
            "-device","qemu-xhci,id=xhci0",
            "-qmp","unix:"+qmp+",server=on,wait=off",
        ],stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,stderr=subprocess.STDOUT)
        act=frontend=restarted=another=None
        try:
            def launch_act(sock):
                return subprocess.Popen([
                    "/guest/r26-actuator","--qmp",qmp,
                    "--socket",sock,"--media",str(media),
                    "--capture",str(root/"keyboard.pcap"),
                    "--journal",str(journal),
                ],stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,
                  stderr=subprocess.PIPE,text=True,bufsize=1)
            act=launch_act(socket)
            yes,detail=ready(act,"R26_L_SOLE_QMP_ACTUATOR_LISTENING=PASS")
            if not yes:
                raise RuntimeError("initial actuator not listening: "+detail)
            frontend=subprocess.Popen(["/guest/r26-frontend","--socket",socket],
                stdin=subprocess.PIPE,stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,text=True,bufsize=1)
            yes,detail=ready(frontend,'"state":"frontend-ready"')
            if not yes:
                raise RuntimeError("frontend not ready: "+detail)
            lease=request(frontend,{"op":"reserve","actor":"approved-agent"})
            if not lease.get("ok"):
                raise RuntimeError("fresh paused guest initial lease refused: "+str(lease))
            epoch,generation=lease["epoch"],lease["generation"]
            base={"actor":"approved-agent","epoch":epoch,"generation":generation}
            for op in ("attach","start"):
                result=request(frontend,dict(base,op=op))
                if not result.get("ok"):
                    raise RuntimeError("initial "+op+" failed: "+str(result))
            print("R26_L5_FRESH_PAUSED_GUEST_BOOTSTRAP=PASS",flush=True)
            buf=b""
            issued=False
            observed=False
            until=time.monotonic()+130
            while time.monotonic()<until and not observed:
                available,_,_=select.select([qemu.stdout],[],[],0.3)
                if not available:
                    continue
                chunk=os.read(qemu.stdout.fileno(),65536)
                if not chunk:
                    break
                buf+=chunk
                while b"\n" in buf:
                    line,buf=buf.split(b"\n",1)
                    if b"R15_GUEST_HID_OBSERVER_READY=PASS" in line and not issued:
                        event=request(frontend,dict(base,op="input",command="key-a-down"))
                        if not event.get("ok"):
                            raise RuntimeError("real guest keydown request failed "+str(event))
                        issued=True
                    if b"R15_GUEST_USB_KEY_A_DOWN=PASS" in line:
                        observed=True
                        break
            if not observed:
                raise RuntimeError("NO real Linux evdev KEY_A down; cannot qualify missing-journal")
            print("R26_L5_REAL_GUEST_EVDEV_KEY_DOWN_BEFORE_CRASH=PASS",flush=True)
            act.kill()
            act.wait(timeout=5)
            state=json.loads(journal.read_text())
            if not state.get("held") or state.get("sequence")!=1:
                raise RuntimeError("journal was not held before missing-file injection")
            journal.unlink()
            if journal.exists():
                raise RuntimeError("simulated journal loss failed")
            print("R26_L5_DISPOSABLE_JOURNAL_LOSS_INJECTED=PASS",flush=True)
            restarted=launch_act(socket2)
            admitted,detail=ready(restarted,"R26_L_SOLE_QMP_ACTUATOR_LISTENING=PASS")
            if admitted:
                another=subprocess.Popen(
                    ["/guest/r26-frontend","--socket",socket2],
                    stdin=subprocess.PIPE,stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,text=True,bufsize=1)
                yes,detail2=ready(another,'"state":"frontend-ready"')
                if not yes:
                    raise RuntimeError("restarted frontend not ready "+detail2)
                response=request(another,{"op":"reserve","actor":"approved-agent"})
                if response.get("ok"):
                    print("R26_L5_RED_MISSING_JOURNAL_RE_ADMITTED_LIVE_GUEST=FAIL",flush=True)
                    raise RuntimeError("P0 FAIL OPEN: missing held journal re-admitted existing live QEMU guest")
                print("R26_L5_STALE_GUEST_RESERVE_DENIED=PASS",flush=True)
            else:
                if restarted.returncode is None:
                    raise RuntimeError("restarted actuator timed out without explicit hold: "+detail)
                print("R26_L5_STALE_GUEST_STARTUP_DENIED=PASS",flush=True)
            print("R26_L5_MISSING_JOURNAL_FAIL_CLOSED=PASS",flush=True)
        finally:
            for p in (another,frontend,restarted,act,qemu):
                stop(p)
            print("R26_L5_ALL_SYNTHETIC_PROCESSES_STOPPED=PASS",flush=True)

if __name__=="__main__":
    main()
