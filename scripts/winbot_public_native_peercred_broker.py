#!/usr/bin/env python3
"""PUBLIC-SYNTHETIC native KVM broker: fixed action, Linux SO_PEERCRED gate.

A disposable root-side broker has the *only* path to one run-owned native
libvirt action. Worker UIDs do NOT get virsh permission. This qualifies OS
principal separation and a fixed-argv mediator, NOT an authenticated claim,
a master immutability lease or same-UID/privileged adversary confinement.
"""
from __future__ import annotations
import json
import os
import pathlib
import pwd
import socket
import stat
import subprocess
import struct
import sys
import time
from scripts import winbot_public_crash_reaper as reaper

ROOT=pathlib.Path("/tmp/winbot-crash-owned")
OUT=pathlib.Path("/tmp/winbot-native-epoch-proof")
SCHEMA="winbot-public-native-peercred-request/v1"
OP="EXACT_OWNED_DISPOSABLE_VM_DESTROY"
SOCK=None
def read_json(data):
    def no_duplicates(pairs):
        out={}
        for k,v in pairs:
            if k in out:raise ValueError("duplicate message key")
            out[k]=v
        return out
    return json.loads(data,object_pairs_hook=no_duplicates)

def bind_socket(path):
    if path.exists() or path.is_symlink():
        raise RuntimeError("preexisting broker socket refused")
    s=socket.socket(socket.AF_UNIX,socket.SOCK_STREAM)
    try:
        s.bind(str(path))
        os.chmod(path,0o666) # peer credentials gate all operations
        st=os.lstat(path)
        if not stat.S_ISSOCK(st.st_mode) or st.st_uid!=os.geteuid():
            raise RuntimeError("broker socket not owned")
        s.listen(3)
        s.settimeout(20)
        return s,st.st_dev,st.st_ino
    except BaseException:
        s.close()
        raise

def server():
    if os.geteuid()!=0 or not hasattr(socket,"SO_PEERCRED"):
        raise RuntimeError("public Linux root disposable broker required")
    owner=reaper.classify(str(ROOT/"ownership-manifest.json"))
    path=path_for(owner["uid"])
    # A new generation MUST use an independently assigned OS principal.
    # Simply changing a self-asserted generation under the old UID is not an
    # authenticated claim, and the old actor must not impersonate the new one.
    worker_uid=pwd.getpwnam("daemon").pw_uid
    stale_uid=pwd.getpwnam("nobody").pw_uid
    try:
        forbidden_uid=pwd.getpwnam("www-data").pw_uid
    except KeyError:
        forbidden_uid=pwd.getpwnam("sys").pw_uid
    if len({worker_uid,stale_uid,forbidden_uid,os.geteuid()})!=4:
        raise RuntimeError("missing distinct current, stale and foreign Unix principals")
    s,dev,ino=bind_socket(path)
    results=[]
    approved_child=None
    approved_pid=None
    try:
        for index in range(6):
            if index==5:
                # The root-side broker, NOT an untrusted client, creates the
                # one accepted generation-2 actor. The kernel authenticates
                # its child PID and Unix UID over SO_PEERCRED. A same-UID
                # attacker cannot nominate itself by supplying epoch=2.
                client_file=pathlib.Path(
                    "/tmp/winbot-peercred-client-"+owner["uid"].replace("-","")+".py")
                st=os.lstat(client_file)
                if not (stat.S_ISREG(st.st_mode) and st.st_uid==os.geteuid()
                        and st.st_nlink==1 and stat.S_IMODE(st.st_mode)==0o644):
                    raise RuntimeError("root-owned immutable synthetic client not proved")
                approved_child=subprocess.Popen(
                    [sys.executable,str(client_file),owner["uid"],"2"],
                    user=worker_uid,group=pwd.getpwnam("daemon").pw_gid,
                    stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True)
                approved_pid=approved_child.pid
            client,_=s.accept()
            with client:
                client.settimeout(9)
                pid,uid,gid=struct.unpack("3i",client.getsockopt(
                    socket.SOL_SOCKET,socket.SO_PEERCRED,struct.calcsize("3i")))
                data=client.recv(4097)
                request=None
                try:
                    if len(data)>4096:raise ValueError("request too large")
                    request=read_json(data)
                    if not isinstance(request,dict):raise ValueError("request object required")
                    if set(request)!={"schema","operation","generation","target_uuid"}:
                        raise ValueError("unrecognized request fields")
                except (ValueError,UnicodeError,TypeError):
                    request={}
                generation=request.get("generation")
                correct=(request.get("schema")==SCHEMA and
                         request.get("operation")==OP and
                         request.get("target_uuid")==owner["uid"] and
                         type(generation) is int)
                if uid==stale_uid:
                    label=("STALE_PRINCIPAL_EPOCH_SPOOF_REFUSED"
                           if generation==2 else "STALE_PRINCIPAL_REFUSED")
                elif uid!=worker_uid:
                    label="FOREIGN_UID_REFUSED"
                elif not correct:
                    label="MALFORMED_OR_FOREIGN_TARGET_REFUSED"
                elif generation!=2:
                    label="STALE_EPOCH_REFUSED"
                elif pid!=approved_pid:
                    label="CURRENT_UID_UNISSUED_PID_REFUSED"
                else:
                    # Import only the fixed, run-owned, native actor function.
                    # It independently checks the SQLite epoch under flock,
                    # the native owner/disk/NIC/network/QEMU chain, then invokes
                    # exactly one literal-argv virsh destroy by UUID.
                    from scripts.winbot_public_live_native_fence import actor
                    code=actor(2,"current")
                    if code!=0:raise RuntimeError("fixed native broker actor failed "+str(code))
                    label="CURRENT_EXACT_OWNER_ACTION_PERFORMED"
                results.append({"ordinal":index+1,"peer_pid":pid,"peer_uid":uid,
                    "label":label,"native_mutation":label=="CURRENT_EXACT_OWNER_ACTION_PERFORMED"})
                client.sendall((json.dumps({"status":label},sort_keys=True)+"\n").encode())
        if approved_child is None:
            raise RuntimeError("no root-issued current actor")
        child_stdout,child_stderr=approved_child.communicate(timeout=15)
        if approved_child.returncode!=0 or (
                "CURRENT_EXACT_OWNER_ACTION_PERFORMED" not in child_stdout):
            raise RuntimeError("root-issued child did not complete "+child_stderr[-250:])
        if ([r["label"] for r in results]!=[
            "FOREIGN_UID_REFUSED","STALE_PRINCIPAL_REFUSED",
            "STALE_PRINCIPAL_EPOCH_SPOOF_REFUSED","STALE_EPOCH_REFUSED",
            "CURRENT_UID_UNISSUED_PID_REFUSED",
            "CURRENT_EXACT_OWNER_ACTION_PERFORMED"] or
            [r["peer_uid"] for r in results]!=[
                forbidden_uid,stale_uid,stale_uid,worker_uid,worker_uid,worker_uid] or
            results[-1]["peer_pid"]!=approved_pid or
            results[-2]["peer_pid"]==approved_pid):
            raise RuntimeError("unexpected native OS broker request sequence")
        proof={
            "schema":"winbot-public-native-peercred-broker/v1",
            "classification":"DISPOSABLE_LINUX_PEER_IDENTITY_AND_FIXED_NATIVE_ACTION",
            "socket_owner_uid":os.geteuid(),
            "root_owned_broker_socket":True,
            "authorized_worker_uid":worker_uid,
            "old_generation_worker_uid":stale_uid,
            "unrelated_worker_uid":forbidden_uid,
            "foreign_uid_refused_before_native_action":True,
            "stale_principal_generational_impersonation_refused":True,
            "distinct_unix_uids_for_generation_one_and_two":True,
            "stale_epoch_refused_before_native_action":True,
            "current_owned_worker_mediated_exact_native_action":True,
            "current_native_action_count":1,
            "same_current_uid_unissued_pid_refused":True,
            "root_broker_forked_only_admitted_current_actor":True,
            "os_so_peercred_pid_and_uid_checked":True,
            "root_issued_current_process_pid":approved_pid,
            "os_so_peercred_identity_checked":True,
            "worker_direct_virsh_authorized":False,
            "request_generation_is_an_authenticated_credential":False,
            "fresh_uid_current_epoch_spoof_by_same_uid_fenced":True,
            "privileged_or_same_uid_bypass_prevented":False, # same UID can still attack/bypass OTHER surfaces
            "external_native_lease_qualified":False,
            "private_winbot_source_executed":False,
            "windows_or_winbot_guest_qualified":False,
            "product_provider_apply_power_destroy_admitted":False,
            "physical_or_production_system_touched":False,
            "requests":results}
        (OUT/"peercred-broker-verdict.json").write_text(
            json.dumps(proof,sort_keys=True,indent=2)+"\n")
        return 0
    finally:
        if approved_child is not None and approved_child.poll() is None:
            approved_child.kill()
            approved_child.wait(timeout=5)
        s.close()
        try:
            st=os.lstat(path)
            if st.st_dev==dev and st.st_ino==ino and stat.S_ISSOCK(st.st_mode):
                path.unlink()
        except FileNotFoundError:pass

def path_for(uid):
    import uuid
    parsed=uuid.UUID(uid)
    if parsed.version!=4 or str(parsed)!=uid:
        raise RuntimeError("noncanonical test run ID")
    return pathlib.Path("/tmp/winbot-peercred-"+parsed.hex+".sock")

def client(uid,generation):
    path=path_for(uid)
    with socket.socket(socket.AF_UNIX,socket.SOCK_STREAM) as c:
        c.settimeout(12)
        c.connect(str(path))
        c.sendall((json.dumps({"schema":SCHEMA,"operation":OP,
            "generation":generation,"target_uuid":uid},sort_keys=True)+"\n").encode())
        response=read_json(c.recv(2048))
    status=response.get("status")
    print(status,flush=True)
    if status=="CURRENT_EXACT_OWNER_ACTION_PERFORMED":return 0
    if status.endswith("_REFUSED"):return 7
    return 5

if __name__=="__main__":
    if len(sys.argv)==2 and sys.argv[1]=="server":
        raise SystemExit(server())
    if len(sys.argv)==4 and sys.argv[1]=="client":
        raise SystemExit(client(sys.argv[2],int(sys.argv[3])))
    raise SystemExit(8)
