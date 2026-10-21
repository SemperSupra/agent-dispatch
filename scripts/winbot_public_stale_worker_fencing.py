#!/usr/bin/env python3
"""Independent PUBLIC-SAFE stale worker / downstream fence oracle.

Not WinBot private implementation and NOT native VM authorization.
A synthetic actuator log is committed in the SAME SQLite transaction as the
generation check. A real VM actuator does not participate in this transaction,
so this proof cannot be promoted to Apply/Power/Destroy.
"""
from __future__ import annotations
import json
import os
import pathlib
import sqlite3
import subprocess
import sys
import tempfile
import time

def dbopen(path):
    c=sqlite3.connect(str(path),timeout=12,isolation_level=None)
    c.execute("PRAGMA busy_timeout=12000")
    c.execute("PRAGMA synchronous=FULL")
    return c

def actor(dbpath, run_id, generation, gate, mode):
    gate=pathlib.Path(gate)
    if mode=="stale":
        ready=gate.parent/"stale-ready"
        ready.write_text("already prepared old owner")
    end=time.monotonic()+15
    while not gate.exists():
        if time.monotonic()>end:return 11
        time.sleep(.006)
    c=dbopen(dbpath)
    try:
        c.execute("BEGIN IMMEDIATE")
        actual=c.execute("SELECT generation,state FROM authority WHERE owner=?",
                          (run_id,)).fetchone()
        if actual!=(generation,"issued"):
            c.execute("ROLLBACK")
            return 7
        changed=c.execute("UPDATE authority SET state='consumed' WHERE "
                          "owner=? AND generation=? AND state='issued'",
                          (run_id,generation)).rowcount
        if changed!=1:
            c.execute("ROLLBACK")
            return 7
        c.execute("INSERT INTO synthetic_actuator_events VALUES(?,?,?)",
                  (run_id,generation,mode))
        c.execute("COMMIT")
        if mode=="commit_before_ack":
            os._exit(98)
        return 0
    except sqlite3.Error:
        try:c.execute("ROLLBACK")
        except sqlite3.Error:pass
        return 12
    finally:
        c.close()

def main():
    with tempfile.TemporaryDirectory(prefix="winbot-public-fence-") as temp:
        root=pathlib.Path(temp)
        path=root/"actuator.sqlite3"
        c=dbopen(path)
        c.execute("PRAGMA journal_mode=WAL")
        c.execute("CREATE TABLE authority("
                  "owner TEXT PRIMARY KEY,generation INTEGER NOT NULL,"
                  "state TEXT NOT NULL CHECK(state IN ('issued','consumed')))")
        c.execute("CREATE TABLE synthetic_actuator_events("
                  "owner TEXT NOT NULL,generation INTEGER NOT NULL,kind TEXT NOT NULL)")
        c.execute("INSERT INTO authority VALUES('owned-disposable-resource',1,'issued')")
        c.close()
        gate=root/"release"
        stale=subprocess.Popen([sys.executable,__file__,"actor",str(path),
                               "owned-disposable-resource","1",str(gate),"stale"])
        # Ensure stale worker really started preparation at generation 1.
        start=time.monotonic()
        while not (root/"stale-ready").exists():
            if time.monotonic()-start>15:
                stale.kill()
                raise RuntimeError("stale worker never armed")
            time.sleep(.006)
        c=dbopen(path)
        c.execute("BEGIN IMMEDIATE")
        current=c.execute("UPDATE authority SET generation=2,state='issued' "
                          "WHERE owner='owned-disposable-resource' AND "
                          "generation=1 AND state='issued'").rowcount
        if current!=1:raise RuntimeError("could not fence generation one")
        c.execute("COMMIT")
        c.close()
        # Distinct actors, same owner, same current-generation claim. Exactly
        # one may append to the SYNTHETIC transactional actuator log.
        new=[subprocess.Popen([sys.executable,__file__,"actor",str(path),
                              "owned-disposable-resource","2",str(gate),"current"])
             for _ in range(12)]
        gate.write_text("go")
        stale_code=stale.wait(timeout=35)
        outcomes=[p.wait(timeout=35) for p in new]
        if stale_code!=7 or outcomes.count(0)!=1 or outcomes.count(7)!=11:
            raise RuntimeError("stale-worker or competing current-fence defect: "+
                               str((stale_code,outcomes)))
        c=dbopen(path)
        events=c.execute("SELECT generation,kind FROM synthetic_actuator_events "
                         "ORDER BY generation").fetchall()
        if events!=[(2,"current")]:raise RuntimeError("stale synthetic event escaped")
        # Advance and emulate post-commit pre-ack crash for the new generation.
        c.execute("BEGIN IMMEDIATE")
        c.execute("UPDATE authority SET generation=3,state='issued' WHERE "
                  "owner='owned-disposable-resource' AND generation=2 AND state='consumed'")
        c.execute("COMMIT")
        c.close()
        crashed=subprocess.run([sys.executable,__file__,"actor",str(path),
             "owned-disposable-resource","3",str(gate),"commit_before_ack"],
             timeout=25)
        retry=actor(path,"owned-disposable-resource",3,gate,"retry")
        if crashed.returncode!=98 or retry!=7:
            raise RuntimeError("committed synthetic action was replayed")
        c=dbopen(path)
        events=c.execute("SELECT generation,kind FROM synthetic_actuator_events "
                         "ORDER BY generation").fetchall()
        c.close()
        if events!=[(2,"current"),(3,"commit_before_ack")]:
            raise RuntimeError("synthetic journal not monotonic/exact: "+repr(events))
        receipt={"schema":"winbot-public-fenced-actuator-v1",
                 "classification":"SYNTHETIC_DB_LOCAL_FENCE_ONLY",
                 "os_name":os.name,
                 "stale_worker_armed_before_generation_advance":True,
                 "stale_worker_after_supersession_refused":True,
                 "concurrent_generation_two_workers":12,
                 "single_current_generation_winner":True,
                 "synthetic_actuator_event_generations":[x[0] for x in events],
                 "commit_before_ack_replay_refused":True,
                 "private_winbot_source_executed":False,
                 "native_vm_actuator_uses_same_atomic_transaction":False,
                 "native_vm_mutation_admitted":False,
                 "master_source_lease_acquired":False,
                 "windows_guest_qualified":False,
                 "physical_system_touched":False}
        dest=pathlib.Path(os.environ.get("WINBOT_PUBLIC_RECEIPT_DIR",temp))
        dest.mkdir(parents=True,exist_ok=True)
        (dest/"stale-worker-fence.json").write_text(
            json.dumps(receipt,sort_keys=True,indent=2)+"\n")
        print("PASS stale worker refused; current winner 1/12; commit-ack replay refused")
    return 0
if __name__=="__main__":
    if len(sys.argv)==1:raise SystemExit(main())
    if len(sys.argv)==7 and sys.argv[1]=="actor":
        raise SystemExit(actor(sys.argv[2],sys.argv[3],int(sys.argv[4]),
                               sys.argv[5],sys.argv[6]))
    raise SystemExit(2)
