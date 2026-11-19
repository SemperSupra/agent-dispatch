#!/usr/bin/env python3
"""Kernel abstract AF_UNIX namespace falsifier; no privileged runner fallback."""
import os
import socket
import subprocess
import sys
def bind():
    s=socket.socket(socket.AF_UNIX,socket.SOCK_STREAM)
    s.bind("\0r27h-public-abstract-owner-probe")
    s.listen()
    return s
if __name__=="__main__":
    if len(sys.argv)>1 and sys.argv[1]=="child":
        with bind():
            print("R27H2_SECOND_NAMESPACE_SAME_ABSTRACT_OWNER_NAME_BOUND=PASS",flush=True)
        sys.exit(0)
    with bind():
        proc=subprocess.run(["unshare","-Urn",sys.executable,os.path.abspath(__file__),"child"],
            text=True,capture_output=True,timeout=15)
        if proc.returncode!=0:
            print("R27H2_UNPRIVILEGED_NETWORK_NAMESPACE=NOT_TESTED",flush=True)
            print("R27H2_REASON="+(proc.stderr.strip()[:160] or str(proc.returncode)),flush=True)
            sys.exit(0)
        if "R27H2_SECOND_NAMESPACE_SAME_ABSTRACT_OWNER_NAME_BOUND=PASS" not in proc.stdout:
            print(proc.stdout,flush=True)
            raise RuntimeError("namespace binding did not yield expected evidence")
        print(proc.stdout.strip(),flush=True)
        print("R27H2_CROSS_NAMESPACE_ABSTRACT_LOCK_COLLISION=REPRODUCED",flush=True)
        print("R27H2_SAME_QEMU_DUAL_ACTUATOR=NOT_TESTED",flush=True)
