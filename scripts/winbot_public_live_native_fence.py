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
        current=call(sys.executable,"-m",
                     "scripts.winbot_public_live_native_fence","actor","2","current")
        if current.returncode!=0:
            raise RuntimeError("fresh native actor failed: "+current.stderr[-450:])
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
                 "fresh_actor_reverified_exact_native_disk_nic_network":True,
                 "one_real_run_owned_virsh_destroy_by_current_actor":True,
                 "native_domain_absent":True,"native_network_absent":True,
                 "owned_overlay_and_master_absent":True,
                 "private_winbot_source_executed":False,
                 "sqlite_itself_enforces_external_native_fencing":False,
                 "uncooperative_actor_hypervisor_fenced":False,
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
