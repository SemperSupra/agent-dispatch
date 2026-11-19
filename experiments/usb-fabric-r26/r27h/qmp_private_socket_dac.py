#!/usr/bin/env python3
"""QMP socket-directory DAC primitive; NOT a QEMU production service test."""
import os
import socket
import subprocess
import sys
import tempfile
from pathlib import Path

def attempt(path):
    try:
        with socket.socket(socket.AF_UNIX) as s:
            s.settimeout(2)
            s.connect(str(path))
        return 0
    except PermissionError:
        return 13
    except OSError as e:
        print("R27H4_CONNECT_UNEXPECTED="+str(e),flush=True)
        return 20

def main():
    if len(sys.argv)==3 and sys.argv[1]=="connect":
        sys.exit(attempt(sys.argv[2]))
    with tempfile.TemporaryDirectory(prefix="r27h4-") as top:
        base=Path(top); base.chmod(0o755)
        private=base/"service-qmp";private.mkdir(mode=0o700)
        endpoint=private/"qmp.sock"
        server=socket.socket(socket.AF_UNIX)
        server.bind(str(endpoint))
        server.listen(3)
        endpoint.chmod(0o666)  # intentionally permissive; parent must defend
        try:
            owner=subprocess.run([sys.executable,__file__,"connect",str(endpoint)],capture_output=True,text=True,timeout=6)
            if owner.returncode!=0:raise RuntimeError("controller cannot access its own QMP socket: "+owner.stderr)
            print("R27H4_SERVICE_PRINCIPAL_QMP_ALLOWED=PASS",flush=True)
            hostile=["sudo","-n","-u","nobody",sys.executable,__file__,"connect",str(endpoint)]
            forbidden=subprocess.run(hostile,capture_output=True,text=True,timeout=6)
            if forbidden.returncode!=13:
                raise RuntimeError("untrusted principal was not denied: "+repr((forbidden.returncode,forbidden.stdout,forbidden.stderr)))
            print("R27H4_DISTINCT_UID_RAW_QMP_DENIED_BY_PRIVATE_DIR=PASS",flush=True)
            private.chmod(0o755)
            exposed=subprocess.run(hostile,capture_output=True,text=True,timeout=6)
            if exposed.returncode!=0:
                raise RuntimeError("positive control could not connect after permission widening: "+repr((exposed.returncode,exposed.stderr)))
            print("R27H4_INSECURE_DIRECTORY_EXPOSURE_CONTROL=PASS",flush=True)
            private.chmod(0o700)
            repeat=subprocess.run(hostile,capture_output=True,text=True,timeout=6)
            if repeat.returncode!=13:raise RuntimeError("relock did not deny distinct UID")
            print("R27H4_PRIVATE_SOCKET_DIR_RELOCK_FAIL_CLOSED=PASS",flush=True)
            print("R27H4_SAME_UID_ATTACK=NOT_TESTED",flush=True)
            print("R27H4_REAL_QEMU_BLUE_CONTROL=NOT_TESTED",flush=True)
            print("R27H4_PRODUCTION_SERVICE_AUTH=NOT_TESTED",flush=True)
        finally:
            server.close()
    print("R27H4_DISPOSABLE_CLEANUP=PASS",flush=True)

if __name__=="__main__":main()
