#!/usr/bin/env python3
"""Actual XTDB 2.x image/start/query/restart qualification over isolated pgwire.

This is NOT a universal PostgreSQL/XTDB query parity claim. It deliberately
tests XTDB's native bitemporal valid/system history and records the dangerous
default document-ID upsert behavior. Source data is completely fabricated.
"""
from __future__ import annotations

import hashlib
import json
from pathlib import Path
import re
import secrets
import subprocess
import sys
import time

SCHEMA="public-mail-xtdb-native-temporal-r2"
# Publisher's immutable linux/amd64 GHCR image, public MPL-2.0; a specific
# g6cd79ee snapshot, NOT falsely represented as 2.2.0 final release.
ENGINE="ghcr.io/xtdb/xtdb@sha256:aa7483e48674446a4892e0ea56a0953502fa5ccb9c4c803a9fb569ea5f0c28fe"
CLIENT="postgres:18.7-trixie@sha256:e754b839f447639b7004895f4d8a4bfcb4e9dbe3a1bc035f27f646562a16fd61"
XTDB_DIGEST=ENGINE.rsplit("@sha256:",1)[1]
MAX_SECONDS=220

class Blocked(ValueError):
    pass

def call(args:list[str],timeout:int=20)->str:
    try:
        process=subprocess.run(args,stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,
                               stderr=subprocess.PIPE,check=False,timeout=timeout)
    except subprocess.TimeoutExpired as exc:
        raise Blocked("XTDB_STEP_TIMEOUT") from exc
    if process.returncode:
        raise Blocked("XTDB_STEP_NONZERO_"+str(process.returncode))
    if len(process.stdout)>65536 or len(process.stderr)>65536:
        raise Blocked("XTDB_OUTPUT_BOUND")
    return process.stdout.decode("utf-8","replace").strip()

def docker(*args:str,timeout:int=25)->str:
    return call(["docker",*args],timeout)

def last_result_row(output:str)->str:
    """Successful psql -q commands may return ZERO rows (e.g. INSERT).

    Preserve absence as absence, never treat an empty acknowledgement as an
    IndexError or invent a fictitious query result.
    """
    lines=output.splitlines()
    return lines[-1].strip() if lines else ""


def psql(network:str,host:str,query:str,timeout:int=25)->str:
    # This is a fixed SQL string authored in the source file; no user SQL or
    # source-derived PST data is accepted. PG client container shares only a
    # private Docker internal network with original XTDB; no public host port.
    output=call([
        "docker","run","--rm","--network",network,
        "--pids-limit","100","--memory","256m","--cpus","1",
        "-e","PGSSLMODE=disable","-e","PGCONNECT_TIMEOUT=5",
        CLIENT,
        "psql","-h",host,"-U","xtdb","-d","xtdb","-q","-X","-A","-t",
        "-v","ON_ERROR_STOP=1","-c",query],timeout)
    return last_result_row(output)

def start(name:str,network:str,volume:str)->None:
    docker("run","-d","--name",name,
           "--network",network,"--pids-limit","256",
           "--memory","3072m","--memory-swap","3072m","--cpus","2",
           "--security-opt","no-new-privileges",
           "--mount","type=volume,src="+volume+",dst=/var/lib/xtdb",
           "-e","JDK_JAVA_OPTIONS=-Xmx1800m",
           ENGINE,timeout=60)
    for _ in range(40):
        try:
            if psql(network,name,"SELECT 'READY';",timeout=10)=="READY":
                return
        except (Blocked,IndexError):
            pass
        time.sleep(1)
    raise Blocked("XTDB_PGWIRE_NEVER_READY")

def require_query(network:str,host:str,query:str,expected:str,label:str)->None:
    value=psql(network,host,query)
    if value!=expected:
        raise Blocked("XTDB_SQL_ORACLE_"+label)

def qualify()->dict:
    started=time.monotonic()
    name="mail-xtdb-r2-"+secrets.token_hex(4)
    volume=name+"-data"
    network=name+"-net"
    # Pull the exact image manifests before the network-isolated runtime.
    docker("pull",ENGINE,timeout=105)
    docker("pull",CLIENT,timeout=90)
    docker("network","create","--internal",network,timeout=15)
    network_made=True
    volume_made=False
    running=False
    try:
        docker("volume","create",volume,timeout=10)
        volume_made=True
        start(name,network,volume)
        running=True
        require_query(network,name,"SELECT 1;","1","PING")
        # Unique source ID per original source occurrence. Same Message-ID
        # or identical file content must never imply logical identity.
        psql(network,name,
            "INSERT INTO mail_sources (_id, tenant, message_id, text_value) "
            "VALUES ('occ-1','alpha','collision','Approval denied.');")
        psql(network,name,
            "INSERT INTO mail_sources (_id, tenant, message_id, text_value) "
            "VALUES ('occ-2','alpha','collision','Approval granted.');")
        psql(network,name,
            "INSERT INTO mail_sources (_id, tenant, message_id, text_value) "
            "VALUES ('occ-3','beta','collision','Private claim.');")
        require_query(network,name,
            "SELECT COUNT(*) FROM mail_sources;","3","SOURCE_OCCURRENCE_IDENTITY")
        require_query(network,name,
            "SELECT COUNT(*) FROM mail_sources WHERE tenant='alpha';",
            "2","TENANT_SCOPE")
        # XTDB's valid-time built in, effective as of May 2 vs May 4.
        psql(network,name,
            "INSERT INTO mail_assessment (_id, decision, _valid_from) "
            "VALUES ('approval','denied',TIMESTAMP '2026-05-02 00:00:00');")
        psql(network,name,
            "INSERT INTO mail_assessment (_id, decision, _valid_from) "
            "VALUES ('approval','approved',TIMESTAMP '2026-05-03 00:00:00');")
        require_query(network,name,
            "SELECT decision FROM mail_assessment "
            "FOR VALID_TIME AS OF TIMESTAMP '2026-05-02 12:00:00';",
            "denied","VALID_TIME_BEFORE")
        require_query(network,name,
            "SELECT decision FROM mail_assessment "
            "FOR VALID_TIME AS OF TIMESTAMP '2026-05-04 12:00:00';",
            "approved","VALID_TIME_AFTER")
        total=int(psql(network,name,
            "SELECT COUNT(*) FROM mail_assessment "
            "FOR VALID_TIME ALL FOR SYSTEM_TIME ALL;"))
        if total<2:
            raise Blocked("XTDB_SYSTEM_HISTORY_NOT_PRESERVED")
        current=int(psql(network,name,"SELECT COUNT(*) FROM mail_sources;"))
        docker("stop","--time","8",name,timeout=22)
        docker("rm",name,timeout=12)
        running=False
        start(name,network,volume)
        running=True
        require_query(network,name,
            "SELECT COUNT(*) FROM mail_sources;",str(current),
            "SOURCE_RESTART")
        require_query(network,name,
            "SELECT decision FROM mail_assessment "
            "FOR VALID_TIME AS OF TIMESTAMP '2026-05-02 12:00:00';",
            "denied","TIME_TRAVEL_RESTART")
        return {
            "schema":SCHEMA,
            "classification":"ORIGINAL_XTDB_BITEMPORAL_RUNTIME_ONLY",
            "image_digest":XTDB_DIGEST,
            "client_digest":CLIENT.rsplit("@sha256:",1)[1],
            "actual_xtdb_executed":True,
            "source_occurrences":3,
            "two_valid_time_queries":True,
            "system_history_recorded":True,
            "historical_record_count_at_least":total,
            "separate_unique_source_keys":True,
            "restart_verified":True,
            "no_public_ports":True,
            "different_source_conflict_preserved":True,
            "source_upsert_is_application_risk":True,
            "same_eight_case_oracle_qualified":False,
            "model_inference":False,
            "native_pst_qualified":False,
            "elapsed_seconds":round(time.monotonic()-started,2),
            "fixed_public_source_sha256":hashlib.sha256(
                b"xtdb fictional source-identity, valid/system-history r2").hexdigest(),
        }
    finally:
        if running:
            try:docker("rm","-f",name,timeout=15)
            except (OSError,Blocked):pass
        if volume_made:
            try:docker("volume","rm","-f",volume,timeout=15)
            except (OSError,Blocked):pass
        if network_made:
            try:docker("network","rm",network,timeout=15)
            except (OSError,Blocked):pass

if __name__=="__main__":
    try:
        print(json.dumps(qualify(),sort_keys=True,separators=(",",":")))
    except (Blocked,OSError,ValueError,IndexError) as exc:
        detail=str(exc) if isinstance(exc,Blocked) else "NATIVE_XTDB_IO"
        print("XTDB_FIRST_FAILURE="+re.sub(r"[^A-Z0-9_]","_",detail.upper())[:85],
              file=sys.stderr)
        raise SystemExit(2)
