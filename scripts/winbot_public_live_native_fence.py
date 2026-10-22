#!/usr/bin/env python3
"""PUBLIC ONLY: stale epoch is refused before a *real*, owned libvirt destroy.

One disposable synthetic KVM domain/network/overlay/master. The launcher
deliberately SIGKILLs the fixture controller after VM start. A stale actor,
armed at generation 1, is released after an atomic generation-2 supersession.
It MUST NOT issue virsh destroy. A generation-2 actor then does an explicitly
owned, independently reobserved, lock-serialized virsh destroy; the exact-owner
test janitor cleans only that VM's remaining domain/network/storage.

The SQLite epoch + POSIX flock is a host-local TEST policy, not native hypervisor
fencing and NOT proof that an uncooperative actor cannot call virsh directly.
"""
from __future__ import annotations
import fcntl
import json
import os
import pathlib
import sqlite3
import subprocess
import sys
import time
from scripts import winbot_public_crash_reaper as reaper

ROOT=pathlib.Path("/tmp/winbot-crash-owned")
RECEIPT=pathlib.Path("/tmp/winbot-native-epoch-proof")
WAIT_SECONDS=20

def call(*argv,env=None,timeout=130):
    return subprocess.run(argv,env=env,check=False,text=True,
                          capture_output=True,timeout=timeout)

def dbconnect():
    c=sqlite3.connect(str(RECEIPT/"epoch.sqlite3"),timeout=10,isolation_level=None)
    c.execute("PRAGMA busy_timeout=10000")
    c.execute("PRAGMA synchronous=FULL")
    return c

def actor(generation:int, action:str):
    if action=="stale":
        (RECEIPT/"stale-ready").write_text("generation-1-armed\n")
        deadline=time.monotonic()+WAIT_SECONDS
        while not (RECEIPT/"release-stale").exists():
            if time.monotonic()>deadline:
                return 9
            time.sleep(.02)
    with open(RECEIPT/"native-actor.lock","r+b") as lock:
        fcntl.flock(lock,fcntl.LOCK_EX)
        db=dbconnect()
        try:
            current=db.execute("SELECT generation FROM epoch WHERE id=1").fetchone()[0]
            if current!=generation:
                return 7
            # Fresh run-owner, disk, network, and actual QEMU-chain readbacks are
            # a mandatory preaction check, not a caller-injected success flag.
            owner=reaper.classify(str(ROOT/"ownership-manifest.json"))
            native=call("virsh","-c","qemu:///system","domstate",owner["uid"])
            if native.returncode or native.stdout.strip().lower()=="shut off":
                return 8
            # Only a current-generation actor, holding the host-local lock, may
            # act on this exact independently reobserved disposable UUID.
            op=call("virsh","-c","qemu:///system","destroy",owner["uid"])
            if op.returncode:
                return 8
            db.execute("INSERT INTO effects(generation,kind) VALUES(?,?)",
                       (generation,"EXACT_OWNED_DISPOSABLE_VM_DESTROY"))
            return 0
        finally:
            db.close()
            fcntl.flock(lock,fcntl.LOCK_UN)

def main():
    if ROOT.exists() or RECEIPT.exists():
        raise RuntimeError("refuse pre-existing owned test roots")
    RECEIPT.mkdir(mode=0o700)
    env=os.environ.copy()
    env.update({"WINBOT_PUBLIC_OVERLAY_EVIDENCE_DIR":str(ROOT),
                "WINBOT_PUBLIC_FATAL_STAGE":"after_domain_started",
                "WINBOT_PUBLIC_SYNTHETIC_FAULTS":"1"})
    try:
        killed=call(sys.executable,"-m","scripts.winbot_public_overlay_readback",
                    env=env,timeout=130)
        if killed.returncode!=-9:
            raise RuntimeError("fixture process was not SIGKILLed")
        manifest=ROOT/"ownership-manifest.json"
        owner=reaper.classify(str(manifest))
        if call("virsh","-c","qemu:///system","dominfo",owner["uid"]).returncode:
            raise RuntimeError("owned VM missing after controller SIGKILL")
        # Separate from cooperative epoch/fencing checks: an untrusted Linux
        # UID tries to bypass the controller and act directly through libvirt.
        # Require OS socket access confinement to reject the destructive call.
        import shutil
        import pwd
        if not shutil.which("runuser") or not shutil.which("virsh"):
            raise RuntimeError("cannot independently test untrusted UID access")
        pwd.getpwnam("nobody")
        unauthorized=call("runuser","-u","nobody","--",
                          shutil.which("virsh"),"-c","qemu:///system",
                          "destroy",owner["uid"],timeout=18)
        if unauthorized.returncode==0:
            raise RuntimeError("untrusted UID directly destroyed owned native VM")
        unchanged=call("virsh","-c","qemu:///system","domstate",owner["uid"])
        if unchanged.returncode or unchanged.stdout.strip().lower()=="shut off":
            raise RuntimeError("untrusted UID bypass changed VM state")
        (RECEIPT/"native-actor.lock").write_bytes(b"0")
        c=dbconnect()
        c.executescript("CREATE TABLE epoch(id INTEGER PRIMARY KEY,generation INTEGER NOT NULL);"
                        "CREATE TABLE effects(generation INTEGER NOT NULL,kind TEXT NOT NULL);"
                        "INSERT INTO epoch VALUES(1,1);")
        c.close()
        stale=subprocess.Popen([sys.executable,"-m",
                   "scripts.winbot_public_live_native_fence","actor","1","stale"],
                   stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True)
        deadline=time.monotonic()+WAIT_SECONDS
        while not (RECEIPT/"stale-ready").exists():
            if stale.poll() is not None:raise RuntimeError("stale worker exited before arm")
            if time.monotonic()>deadline:raise RuntimeError("stale worker did not arm")
            time.sleep(.02)
        c=dbconnect()
        c.execute("BEGIN IMMEDIATE")
        c.execute("UPDATE epoch SET generation=2 WHERE id=1 AND generation=1")
        c.execute("COMMIT")
        c.close()
        (RECEIPT/"release-stale").write_text("go\n")
        stale_out,stale_err=stale.communicate(timeout=WAIT_SECONDS)
        if stale.returncode!=7:
            raise RuntimeError("stale OS actor was not refused: "+
                               str(stale.returncode)+" "+stale_err[-250:])
        # The stale actor never changed native VM state.
        state=call("virsh","-c","qemu:///system","domstate",owner["uid"])
        if state.returncode or state.stdout.strip().lower()=="shut off":
            raise RuntimeError("stale actor unexpectedly destroyed native domain")
        # A separate root-only broker is the sole native command issuer.
        # Two hostile worker requests must be refused by Linux SO_PEERCRED
        # and epoch before allowing one fixed UUID-scoped native action.
        from scripts import winbot_public_native_peercred_broker as broker
        socket_path=broker.path_for(owner["uid"])
        # The hosted runner's checkout may not be traversable by unrelated
        # UIDs. Stage a tiny public-only client in /tmp, root-owned, readable
        # but NOT writable by the test principals; no source-bearing imports.
        client_source=pathlib.Path(__file__).with_name(
                        "winbot_public_native_peercred_client.py").read_bytes()
        if len(client_source)>8192:
            raise RuntimeError("unexpectedly large unprivileged test client")
        client_path=pathlib.Path("/tmp/winbot-peercred-client-"+owner["uid"].replace("-","")+".py")
        descriptor=os.open(client_path,os.O_CREAT|os.O_EXCL|os.O_WRONLY|os.O_NOFOLLOW,0o644)
        with os.fdopen(descriptor,"wb") as stream:
            stream.write(client_source)
            stream.flush()
        os.chmod(client_path,0o644)
        server=subprocess.Popen([sys.executable,"-m",
                        "scripts.winbot_public_native_peercred_broker","server"],
                        stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True)
        try:
            until=time.monotonic()+WAIT_SECONDS
            while not socket_path.exists():
                if server.poll() is not None:
                    raise RuntimeError("native peercred broker exited before bind")
                if time.monotonic()>until:
                    raise RuntimeError("native peercred broker did not bind")
                time.sleep(.025)
            try:
                pwd.getpwnam("www-data")
                foreign_user="www-data"
            except KeyError:
                foreign_user="sys"
            for identity,epoch,refusal in (
                (foreign_user,"2","FOREIGN_UID_REFUSED"),
                ("nobody","1","STALE_PRINCIPAL_REFUSED"),
                ("nobody","2","STALE_PRINCIPAL_EPOCH_SPOOF_REFUSED"),
                ("daemon","1","STALE_EPOCH_REFUSED"),
                ("daemon","2","CURRENT_UID_UNISSUED_PID_REFUSED")
            ):
                attempt=call("runuser","-u",identity,"--",
                             sys.executable,str(client_path),owner["uid"],epoch,timeout=15)
                if attempt.returncode!=7 or refusal not in attempt.stdout:
                    raise RuntimeError("broker denied principal/epoch improperly: "+
                        identity+"/"+epoch+" "+str(attempt.returncode)+
                        " "+attempt.stderr[-240:])
                vm=call("virsh","-c","qemu:///system","domstate",owner["uid"])
                if vm.returncode or vm.stdout.strip().lower()=="shut off":
                    raise RuntimeError("refused principal mutated live owned KVM")
            # Even the current-generation unprivileged UID cannot directly
            # access the privileged native libvirt actuator socket.
            direct=call("runuser","-u","daemon","--",
                        shutil.which("virsh"),"-c","qemu:///system",
                        "destroy",owner["uid"],timeout=18)
            if direct.returncode==0:
                raise RuntimeError("current broker client bypassed native socket")
            vm=call("virsh","-c","qemu:///system","domstate",owner["uid"])
            if vm.returncode or vm.stdout.strip().lower()=="shut off":
                raise RuntimeError("direct bypass negative changed owned KVM")
            # The root-side broker creates its own one-shot generation-2
            # client; the controller is not permitted to nominate a PID.
            stdout,stderr=server.communicate(timeout=WAIT_SECONDS)
            if server.returncode:
                raise RuntimeError("privileged fixed-argv mediator failed: "+stderr[-450:])
            broker_proof=json.loads((RECEIPT/"peercred-broker-verdict.json").read_text())
            if not (broker_proof["foreign_uid_refused_before_native_action"] and
                    broker_proof["stale_epoch_refused_before_native_action"] and
                    broker_proof["current_native_action_count"]==1 and
                    broker_proof["stale_principal_generational_impersonation_refused"] and
                    broker_proof["distinct_unix_uids_for_generation_one_and_two"] and
                    broker_proof["os_so_peercred_identity_checked"] and
                    broker_proof["same_current_uid_unissued_pid_refused"] and
                    broker_proof["root_broker_forked_only_admitted_current_actor"] and
                    broker_proof["os_so_peercred_pid_and_uid_checked"]):
                raise RuntimeError("native mediator evidence incomplete")
        finally:
            if server.poll() is None:
                server.terminate()
                try:server.wait(timeout=5)
                except subprocess.TimeoutExpired:server.kill()
            try:
                if (client_path.exists() and not client_path.is_symlink() and
                    client_path.stat().st_uid==os.geteuid()):
                    client_path.unlink()
            except OSError:
                pass
        c=dbconnect()
        effects=c.execute("SELECT generation,kind FROM effects").fetchall()
        c.close()
        if effects!=[(2,"EXACT_OWNED_DISPOSABLE_VM_DESTROY")]:
            raise RuntimeError("native effect journal not one-fenced winner")
        state=call("virsh","-c","qemu:///system","domstate",owner["uid"])
        if state.returncode or state.stdout.strip().lower()!="shut off":
            raise RuntimeError("native VM not stopped by current generation actor")
        result=reaper.main(str(manifest))
        if result!=0:
            raise RuntimeError("exact-owner recovery failed after fenced native destroy")
        cleanup=json.loads((ROOT/"recovery.json").read_text())
        if not all(cleanup[k] for k in
            ("domain_absent","network_absent","overlay_absent","master_fixture_absent")):
            raise RuntimeError("owned native resources still present")
        receipt={"schema":"winbot-public-native-epoch-fence/v1",
                 "classification":"RUN_OWNED_DISPOSABLE_LINUX_HOST_LOCK_ONLY",
                 "actual_libvirt_kvm_vm_created":True,
                 "controller_sigkill_observed":True,
                 "stale_actor_armed_before_supersession":True,
                 "stale_actor_refused_before_native_call":True,
                 "stale_actor_native_vm_unchanged":True,
                 "independent_unprivileged_uid_direct_virsh_destroy_refused":True,
                 "privileged_or_same_uid_bypass_not_qualified":True,
                 "fresh_actor_reverified_exact_native_disk_nic_network":True,
                 "one_real_run_owned_virsh_destroy_by_current_actor":True,
                 "fixed_root_native_broker_so_peercred_qualified":True,
                 "foreign_principal_broker_refused":True,
                 "stale_generation_same_principal_refused":True,
                 "authorized_principal_mediated_exact_native_destroy":True,
                 "stale_uid_claiming_current_epoch_refused_before_native_call":True,
                 "current_uid_direct_libvirt_destroy_refused":True,
                 "unissued_same_current_uid_pid_spoof_refused":True,
                 "root_issued_only_one_current_actor_pid":True,
                 "fresh_generation_worker_distinct_unix_identity":True,
                 "client_supplied_epoch_not_authenticated_credential":True,
                 "native_domain_absent":True,"native_network_absent":True,
                 "owned_overlay_and_master_absent":True,
                 "private_winbot_source_executed":False,
                 "sqlite_itself_enforces_external_native_fencing":False,
                 "uncooperative_actor_hypervisor_fenced":False,
                 "privileged_native_bypass_fenced":False,
                 "same_uid_forgery_fenced":False,
                 "master_immutability_lease_qualified":False,
                 "product_native_vm_mutation_admitted":False,
                 "windows_guest_qualified":False,
                 "physical_host_or_production_touched":False}
        (RECEIPT/"native-epoch-verdict.json").write_text(
            json.dumps(receipt,sort_keys=True,indent=2)+"\n")
        print("PASS: stale generation refused; fresh owned virsh destroy; zero residue")
        return 0
    finally:
        # Test-only exact-owner recovery on unexpected failure. Never guess
        # from a workcell name or delete an unverified foreign VM.
        manifest=ROOT/"ownership-manifest.json"
        if manifest.is_file():
            try:reaper.main(str(manifest))
            except Exception as exc:print("JANITOR_REFUSED:"+str(exc),file=sys.stderr)
if __name__=="__main__":
    if len(sys.argv)==1:raise SystemExit(main())
    if len(sys.argv)==4 and sys.argv[1]=="actor":
        raise SystemExit(actor(int(sys.argv[2]),sys.argv[3]))
    raise SystemExit(2)
