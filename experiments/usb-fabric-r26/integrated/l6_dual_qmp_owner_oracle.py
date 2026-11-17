#!/usr/bin/env python3
"""R26-L6 real-QMP RED/BLUE: exactly one actuator process per socket namespace.

The two test frontends are unprivileged *synthetic* selectors, not real auth.
QEMU VM never starts execution; no physical USB/host agent/privileges are used.
"""
import json
from pathlib import Path
import select
import subprocess
import tempfile
import time

def ready(proc,needle,limit=12):
    until=time.monotonic()+limit
    while time.monotonic()<until:
        if proc.poll() is not None:
            err=proc.stderr.read() if proc.stderr else ""
            return False,err
        r,_,_=select.select([proc.stdout],[],[],0.2)
        if r:
            line=proc.stdout.readline()
            if needle in line:return True,line
    return False,"readiness timeout"

def request(p,payload):
    p.stdin.write(json.dumps(payload)+"\n")
    p.stdin.flush()
    r,_,_=select.select([p.stdout],[],[],12)
    if not r:raise RuntimeError("frontend hung")
    line=p.stdout.readline()
    if not line:raise RuntimeError("frontend closed unexpectedly")
    return json.loads(line)

def kill(p):
    if p is not None and p.poll() is None:
        p.kill()
        p.wait(timeout=5)

def main():
    with tempfile.TemporaryDirectory(dir="/tmp",prefix="r26-l6-") as d:
        root=Path(d)
        media=root/"synthetic.img"
        media.write_bytes(b"R26-L6-NO-REAL-USB"+bytes(4096))
        qmp_a=str(root/"qmp-a.sock")
        qmp_b=str(root/"qmp-b.sock")
        journal=str(root/"held.json")
        a1=a2=a3=f1=f2=f3=None
        qemu=subprocess.Popen([
            "qemu-system-x86_64","-machine","q35","-accel","tcg",
            "-cpu","qemu64","-m","1024M","-smp","1","-S",
            "-nodefaults","-display","none","-monitor","none",
            "-serial","stdio","-net","none","-no-reboot",
            "-kernel","/guest/kernel","-initrd","/guest/initrd.gz",
            "-append","console=ttyS0 rdinit=/init loglevel=7 panic=-1",
            "-device","qemu-xhci,id=xhci0",
            "-qmp","unix:"+qmp_a+",server=on,wait=off",
            "-qmp","unix:"+qmp_b+",server=on,wait=off",
        ],stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,stderr=subprocess.STDOUT)
        try:
            def actuator(n):
                return subprocess.Popen([
                    "/guest/r26-actuator","--qmp",(qmp_b if n=="second" else qmp_a),
                    "--socket",str(root/("api-"+n+".sock")),
                    "--media",str(media),"--capture",str(root/"hid.pcap"),
                    "--journal",journal,
                ],stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,
                  stderr=subprocess.PIPE,text=True,bufsize=1)
            def frontend(n):
                p=subprocess.Popen([
                    "/guest/r26-frontend","--socket",str(root/("api-"+n+".sock"))
                ],stdin=subprocess.PIPE,stdout=subprocess.PIPE,
                  stderr=subprocess.PIPE,text=True,bufsize=1)
                yes,msg=ready(p,'"state":"frontend-ready"')
                if not yes:raise RuntimeError("frontend "+n+" failed "+msg)
                return p
            a1=actuator("first")
            yes,msg=ready(a1,"R26_L_SOLE_QMP_ACTUATOR_LISTENING=PASS")
            if not yes:raise RuntimeError("first actuator did not start "+msg)
            f1=frontend("first")
            first=request(f1,{"op":"reserve","actor":"approved-agent"})
            if not first.get("ok"):raise RuntimeError("first lease not acquired "+str(first))
            print("R26_L6_FIRST_ACTUATOR_WITH_REAL_QMP=PASS",flush=True)

            # Same QEMU QMP socket and held journal, different IPC endpoints.
            a2=actuator("second")
            both,msg=ready(a2,"R26_L_SOLE_QMP_ACTUATOR_LISTENING=PASS")
            if both:
                f2=frontend("second")
                second=request(f2,{"op":"reserve","actor":"approved-agent"})
                if second.get("ok"):
                    print("R26_L6_RED_DUAL_ACTUATOR_SAME_QMP_LEASES=FAIL",flush=True)
                    raise RuntimeError("P0: two actuator processes admitted same QMP guest")
                print("R26_L6_SECOND_ACTUATOR_CLIENT_DENIED=PASS",flush=True)
            else:
                # A QMP greeting timeout or one-listener limit is NOT OS-level
                # actuator exclusivity. Demand an explicit OS lock failure.
                if "R26_L6_QMP_OWNER_LOCK_BUSY=PASS" not in msg:
                    print("R26_L6_RED_NO_OS_OWNER_FENCE="+msg.strip()[-240:],flush=True)
                    raise RuntimeError("P0: no explicit OS owner lock rejection")
                print("R26_L6_SECOND_ACTUATOR_OS_LOCK_DENIED=PASS",flush=True)

            # Host-level owner should transfer only AFTER actual first exit.
            kill(f1)
            f1=None
            kill(a1)
            a1=None
            a3=actuator("third")
            yes,msg=ready(a3,"R26_L_SOLE_QMP_ACTUATOR_LISTENING=PASS")
            if not yes:raise RuntimeError("post-SIGKILL owner cannot recover "+msg)
            f3=frontend("third")
            third=request(f3,{"op":"reserve","actor":"approved-agent"})
            if not third.get("ok"):
                raise RuntimeError("post-SIGKILL new incarnation denied "+str(third))
            print("R26_L6_OS_OWNER_LOCK_RELEASE_AFTER_SIGKILL=PASS",flush=True)
            print("R26_L6_REAL_QMP_SINGLE_PROCESS_OWNER=PASS",flush=True)
        finally:
            for p in (f3,f2,f1,a3,a2,a1,qemu):kill(p)
            print("R26_L6_ALL_DISPOSABLE_PROCESSES_STOPPED=PASS",flush=True)

if __name__=="__main__":
    main()
