#!/usr/bin/env python3
"""PUBLIC, SANITIZED SQLite fencing experiment; NO private WinBot implementation.

An unrelated minimal SQLite counter serves only to independently test atomic
single-winner claims, generation rollover, crash-before-commit rollback,
cross-process restart persistence, and two host OSes. No VM APIs or cleanup.
"""
from __future__ import annotations
import concurrent.futures
import hashlib
import json
import os
import pathlib
import sqlite3
import subprocess
import sys
import tempfile
import time

WORKER_COUNT=12

def connection(path):
    con=sqlite3.connect(str(path),isolation_level=None,timeout=10)
    con.execute("PRAGMA busy_timeout=10000")
    con.execute("PRAGMA synchronous=FULL")
    return con

def worker(dbpath, start, generation, mode):
    if mode=="crash":
        db=connection(dbpath)
        db.execute("BEGIN IMMEDIATE")
        db.execute("UPDATE tickets SET state='consumed' WHERE generation=?",
                   (generation,))
        os._exit(97)  # no SQLite COMMIT and no Python finally
    limit=time.monotonic()+15
    while not pathlib.Path(start).exists():
        if time.monotonic()>limit:return 5
        time.sleep(.004)
    db=connection(dbpath)
    try:
        db.execute("BEGIN IMMEDIATE")
        state=db.execute("SELECT generation,state FROM tickets ORDER BY generation DESC LIMIT 1").fetchone()
        result=(state==(generation,"issued"))
        if result:
            changed=db.execute("UPDATE tickets SET state='consumed' WHERE "
                "generation=? AND state='issued'",(generation,)).rowcount
            result=changed==1
        db.execute("COMMIT")
        return 0 if result else 7
    except sqlite3.Error:
        db.execute("ROLLBACK")
        return 6
    finally:db.close()

def main():
    with tempfile.TemporaryDirectory(prefix="winbot-public-synthetic-ledger-") as dirname:
        base=pathlib.Path(dirname)
        dbpath=base/"synthetic.sqlite3"
        con=connection(dbpath)
        con.execute("PRAGMA journal_mode=WAL")
        con.executescript("CREATE TABLE tickets(generation INTEGER PRIMARY KEY,"
                          "state TEXT NOT NULL CHECK(state IN ('issued','consumed','superseded')));"
                          "INSERT INTO tickets VALUES(1,'issued');")
        con.close()
        # 12 genuinely independent operating-system processes race the same
        # durable one-use state; exactly one may successfully consume.
        signal=base/"start"
        processes=[subprocess.Popen([sys.executable,__file__,"worker",
            str(dbpath),str(signal),"1","consume"]) for _ in range(WORKER_COUNT)]
        signal.write_text("GO")
        outcomes=[p.wait(timeout=30) for p in processes]
        if outcomes.count(0)!=1 or outcomes.count(7)!=WORKER_COUNT-1:
            raise RuntimeError("multi-process one-use race failed "+str(outcomes))
        con=connection(dbpath)
        state=con.execute("SELECT state FROM tickets WHERE generation=1").fetchone()[0]
        if state!="consumed":raise RuntimeError("one-use state not committed")
        con.execute("INSERT INTO tickets VALUES(2,'issued')")
        con.close()
        crash=subprocess.run([sys.executable,__file__,"worker",
                str(dbpath),str(signal),"2","crash"],timeout=15)
        if crash.returncode!=97:raise RuntimeError("expected native crash exit")
        con=connection(dbpath)
        recovered=con.execute("SELECT state FROM tickets WHERE generation=2").fetchone()[0]
        if recovered!="issued":raise RuntimeError("uncommitted crash consumed claim")
        con.execute("UPDATE tickets SET state='superseded' WHERE generation=2")
        con.execute("INSERT INTO tickets VALUES(3,'issued')")
        con.close()
        stale=worker(dbpath,signal,2,"consume")
        if stale!=7:raise RuntimeError("stale generation accepted")
        accepted=worker(dbpath,signal,3,"consume")
        replay=worker(dbpath,signal,3,"consume")
        if accepted!=0 or replay!=7:raise RuntimeError("new generation/replay failed")
        con=connection(dbpath)
        rows=con.execute("SELECT generation,state FROM tickets ORDER BY generation").fetchall()
        con.close()
        if rows!=[(1,"consumed"),(2,"superseded"),(3,"consumed")]:
            raise RuntimeError("unexpected durable tombstones "+repr(rows))
        proof={
            "schema":"winbot-public-sqlite-fence-batch/v1",
            "classification":"INDEPENDENT_SYNTHETIC_SQLITE_PRIMITIVE_ONLY",
            "os_name":os.name,"python_version":sys.version.split()[0],
            "separate_competing_processes":WORKER_COUNT,
            "single_winner_consumption":True,
            "rejected_competing_consumers":WORKER_COUNT-1,
            "crash_before_commit_rolled_back":True,
            "durable_replay_rejected":True,"stale_generation_rejected":True,
            "durable_tombstones":rows,
            "private_winbot_code_executed":False,
            "ledger_origin_authenticated":False,
            "source_master_lease_acquired":False,
            "vm_mutation_or_recovery_admitted":False,
            "windows_or_winbot_guest_qualified":False,
            "physical_host_deployment":False
        }
        out=pathlib.Path(os.environ.get("WINBOT_PUBLIC_RECEIPT_DIR",dirname))
        out.mkdir(parents=True,exist_ok=True)
        (out/"fencing-proof.json").write_text(json.dumps(proof,sort_keys=True,indent=2)+"\n")
        print(json.dumps({"multi_process":WORKER_COUNT,"winner":1,
            "crash_rollback":True,"stale_fenced":True,"replay_rejected":True}))
    return 0

if __name__=="__main__":
    if len(sys.argv)==1: raise SystemExit(main())
    if len(sys.argv)==6 and sys.argv[1]=="worker":
        raise SystemExit(worker(sys.argv[2],sys.argv[3],int(sys.argv[4]),sys.argv[5]))
    raise SystemExit(2)
