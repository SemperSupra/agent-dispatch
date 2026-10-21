#!/usr/bin/env python3
"""PUBLIC-SAFE standalone unprivileged Unix client for the bounded KVM broker.

Has no access to private WinBot source or native hypervisor credentials.
No repo imports, network API, subprocess, or arbitrary native command string.
"""
from __future__ import annotations
import json
import socket
import sys
import uuid

SCHEMA="winbot-public-native-peercred-request/v1"
OP="EXACT_OWNED_DISPOSABLE_VM_DESTROY"
def main(run_uuid, generation):
    owner=uuid.UUID(run_uuid)
    if owner.version!=4 or str(owner)!=run_uuid:return 8
    if generation not in (1,2):return 8
    path="/tmp/winbot-peercred-"+owner.hex+".sock"
    with socket.socket(socket.AF_UNIX,socket.SOCK_STREAM) as connection:
        connection.settimeout(12)
        connection.connect(path)
        request={"schema":SCHEMA,"operation":OP,"generation":generation,
                 "target_uuid":run_uuid}
        connection.sendall((json.dumps(request,sort_keys=True)+"\n").encode())
        result=json.loads(connection.recv(2048))
    status=result.get("status","INVALID")
    print(status,flush=True)
    if status=="CURRENT_EXACT_OWNER_ACTION_PERFORMED":return 0
    if status in ("FOREIGN_UID_REFUSED","STALE_EPOCH_REFUSED",
                  "STALE_PRINCIPAL_REFUSED","STALE_PRINCIPAL_EPOCH_SPOOF_REFUSED",
                  "MALFORMED_OR_FOREIGN_TARGET_REFUSED"):return 7
    return 8
if __name__=="__main__":
    if len(sys.argv)!=3:raise SystemExit(8)
    try:raise SystemExit(main(sys.argv[1],int(sys.argv[2])))
    except (OSError,ValueError,TypeError):raise SystemExit(8)
