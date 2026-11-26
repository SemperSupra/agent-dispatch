#!/usr/bin/env python3
"""Real original actuator + QEMU, separate UID, read-only policy; no guest HID claim."""
import json, os, pathlib, socket, subprocess, sys, tempfile, time

def wait_socket(p, proc):
    end = time.monotonic()+12
    while not p.exists():
        if proc.poll() is not None or time.monotonic()>end:
            raise RuntimeError("process exited or socket unavailable")
        time.sleep(.04)

def terminate(p):
    if p is not None and p.poll() is None:
        p.terminate()
        try: p.wait(timeout=5)
        except subprocess.TimeoutExpired: p.kill(); p.wait(timeout=5)

actuator = sys.argv[1]
with tempfile.TemporaryDirectory(prefix="usb-native-service-") as d:
    root=pathlib.Path(d); root.chmod(0o711)
    private=root/"private"; private.mkdir(mode=0o700)
    frontend=root/"frontend"; frontend.mkdir(mode=0o710)
    qpath=private/"q.sock"; fpath=frontend/"a.sock"
    media=private/"disk"; media.write_bytes(b"\0"*512)
    gid=os.getegid()
    q=a=None
    try:
        q=subprocess.Popen(["qemu-system-x86_64","-machine","q35,accel=tcg","-m","128","-nodefaults","-display","none","-S","-qmp",f"unix:{qpath},server=on,wait=off"],stdout=subprocess.DEVNULL,stderr=subprocess.PIPE)
        wait_socket(qpath,q)
        args=[actuator,"-qmp",str(qpath),"-qmp-protected-pid",str(q.pid),"-socket",str(fpath),"-journal",str(private/"held.json"),"-media",str(media),"-capture",str(private/"cap"),"-protected-frontend","-authorized-peer-uid","65534","-permitted-operations","status,ports"]
        a=subprocess.Popen(args,stdout=subprocess.PIPE,stderr=subprocess.STDOUT)
        wait_socket(fpath,a)
        child = """
import json,os,socket,sys
assert os.geteuid()==int(sys.argv[1]) and os.getegid()==int(sys.argv[4]) and not os.getgroups()
s=socket.socket(socket.AF_UNIX);s.settimeout(4);s.connect(sys.argv[2])
s.sendall(b'{"op":"status"}\\n')
if sys.argv[1]=="65533":
 try: data=s.recv(4096)
 except ConnectionResetError: data=b""
 assert data==b"",data
 print("WRONG_UID_NO_FRONTEND_RESPONSE=PASS");sys.exit(0)
f=s.makefile("rb")
r=json.loads(f.readline());assert r["ok"] and r["port"]["state"]=="available",r
s.sendall(b'{"op":"reserve","actor":"approved-agent"}\\n')
r=json.loads(f.readline());assert not r["ok"] and "outside authenticated" in r["error"],r
try:
 x=socket.socket(socket.AF_UNIX);x.connect(sys.argv[3]);raise AssertionError("raw QMP admitted")
except PermissionError: pass
print("DISTINCT_UID_STATUS_ALLOWED_MUTATION_RAW_QMP_DENIED=PASS")
"""
        for uid in (65534,65533):
            r=subprocess.run(["sudo","-n","--","setpriv","--reuid="+str(uid),"--regid="+str(gid),"--clear-groups","--","python3","-c",child,str(uid),str(fpath),str(qpath),str(gid)],capture_output=True,text=True,timeout=12)
            print(r.stdout,end="")
            if r.returncode: raise RuntimeError(r.stderr)
        print("ORIGINAL_ACTUATOR_PROTECTED_FRONTEND_REAL_QEMU=PASS")
    finally:
        terminate(a);terminate(q)
        if a is not None:
            print(a.stdout.read().decode(errors="replace")[-4000:])
