#!/usr/bin/env python3
"""XTDB R3: original server versus the exact immutable SQLite/PG temporal gold.

Public fictional source fixtures only. This qualifies SQL predicates over
valid-at and knowledge-at; the XTDB-native transaction clock remains separate.
Do not infer native source immutability from a successful historical query.
"""
from __future__ import annotations

import hashlib
import importlib.util
import json
from pathlib import Path
import re
import secrets
import subprocess
import sys
import time

ROOT=Path(__file__).resolve().parents[1]
BASELINE=ROOT/"tools/mail-evidence-challenge/temporal_sqlite/qualify.py"
SCHEMA="mail-native-xtdb-frozen-eight-case-r3"
XTDB_RUNTIME=ROOT/"scripts/qualify_temporal_xtdb.py"

# Independently recorded answer oracle; not inferred from the engine being tested.
GOLD=(
    ("before_any","alpha","2026-05-01T12:00:00Z","2026-05-11T00:00:00Z","NEITHER",()),
    ("early_known","alpha","2026-05-03T12:00:00Z","2026-05-04T00:00:00Z","REFUTED",("a1",)),
    ("late_retro","alpha","2026-05-03T12:00:00Z","2026-05-11T00:00:00Z","BOTH",("a1","a3","a4")),
    ("pre_arrival","alpha","2026-05-04T12:00:00Z","2026-05-04T12:00:00Z","REFUTED",("a1",)),
    ("later_known","alpha","2026-05-04T12:00:00Z","2026-05-06T00:00:00Z","BOTH",("a1","a2")),
    ("late_reacquisition","alpha","2026-05-04T12:00:00Z","2026-05-07T00:00:00Z","BOTH",("a1","a2","a4")),
    ("beta_private","beta","2026-05-03T12:00:00Z","2026-05-11T00:00:00Z","SUPPORTED",("beta1",)),
    ("alpha_unknown","alpha","2026-05-01T12:00:00Z","2026-05-02T08:00:00Z","NEITHER",()),
)

class Blocked(ValueError):
    pass

def baseline_source()->tuple:
    spec=importlib.util.spec_from_file_location("frozen_sqlite_r1",BASELINE)
    if spec is None or spec.loader is None:
        raise Blocked("FROZEN_BASELINE_MISSING")
    module=importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    sources,claims=module.SOURCE_ROWS,module.CLAIM_ROWS
    if len(sources)!=6 or len(claims)!=6:
        raise Blocked("FROZEN_BASELINE_ROW_COUNT_DRIFT")
    by_id={row[0]:row for row in sources}
    if len(by_id)!=len(sources):
        raise Blocked("SOURCE_ID_COLLISION_IN_FIXTURE")
    for claim in claims:
        source=by_id.get(claim[1])
        if source is None or claim[-1] not in source[-1]:
            raise Blocked("CLAIM_NOT_ANCHORED_TO_SOURCE")
        if source[3]!=claim[2] or claim[5] not in ("actual","planned"):
            raise Blocked("TENANT_OR_MODALITY_FIXTURE_DRIFT")
        # All six frozen source claims have unbounded valid-to intervals.
        # A column whose values are all NULL may not be present in XTDB's
        # dynamically inferred SQL schema. Do not silently drop any finite end.
        if claim[7] is not None:
            raise Blocked("FINITE_VALID_TO_UNQUALIFIED_IN_R3")
    return sources,claims,module.digest

def load_original()->object:
    spec=importlib.util.spec_from_file_location("original_xtdb_r2",XTDB_RUNTIME)
    if spec is None or spec.loader is None:raise Blocked("XTDB_RUNTIME_MISSING")
    mod=importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    if not mod.ENGINE.startswith("ghcr.io/xtdb/xtdb@sha256:"):
        raise Blocked("UNPINNED_ENGINE")
    if not mod.CLIENT.startswith("postgres:18.7-trixie@sha256:"):
        raise Blocked("UNPINNED_CLIENT")
    return mod

def quote(value)->str:
    return "NULL" if value is None else "'"+str(value).replace("'","''")+"'"

def write_original(mod,network:str,host:str,table:str,columns:tuple[str,...],
                   rows:list[tuple])->None:
    for row in rows:
        if len(row)!=len(columns):
            raise Blocked("INPUT_SCHEMA_COLUMN_COUNT_MISMATCH")
        stmt=("INSERT INTO "+table+" ("+",".join(columns)+") VALUES ("+
              ",".join(quote(v) for v in row)+");")
        mod.psql(network,host,stmt,timeout=25)

def xtdb_rows(mod,network:str,host:str,statement:str)->list[tuple[str,...]]:
    # Original psql client and private, internal-only bridge. Retain ALL rows,
    # unlike R2's last-result-row helper intended for scalar SELECT.
    command=[
        "docker","run","--rm","--network",network,"--pids-limit","100",
        "--memory","256m","--cpus","1",
        "-e","PGSSLMODE=disable","-e","PGCONNECT_TIMEOUT=5",
        mod.CLIENT,"psql","-h",host,"-U","xtdb","-d","xtdb",
        "-q","-X","-A","-t","-F","|","-v","ON_ERROR_STOP=1",
        "-c",statement
    ]
    try:
        process=subprocess.run(command,stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,stderr=subprocess.PIPE,
            timeout=30,check=False)
    except subprocess.TimeoutExpired as exc:
        raise Blocked("XTDB_SELECT_TIMEOUT") from exc
    if process.returncode:
        # Only a bounded error *category* appears in CI; never raw SQL or
        # DB stderr. Input is intentionally fictional and hard-coded.
        errors=process.stderr.decode("utf-8","replace").lower()[:4096]
        category="OTHER_SQL"
        for marker,value in (
            ("column","COLUMN_UNRESOLVED"),
            ("undefined name","COLUMN_UNRESOLVED"),
            ("cannot resolve","COLUMN_UNRESOLVED"),
            ("type mismatch","TYPE_MISMATCH"),
            ("parse error","SQL_PARSE"),
            ("syntax error","SQL_SYNTAX"),
            ("unknown table","TABLE_UNRESOLVED"),
            ("table not found","TABLE_UNRESOLVED"),
        ):
            if marker in errors:
                category=value
                break
        # The static fixture and statement are entirely fictional. Preserve
        # only the first compact, non-sensitive SQL error's *category text*.
        for line in errors.splitlines():
            if "error:" in line:
                detail=line.split("error:",1)[1].strip()
                category=category+"_"+re.sub(r"[^a-z0-9]+","_",detail).strip("_")[:48].upper()
                break
        raise Blocked("XTDB_SELECT_NONZERO_"+str(process.returncode)+"_"+category)
    if len(process.stdout)>65536 or len(process.stderr)>65536:
        raise Blocked("XTDB_QUERY_OUTPUT_BOUND")
    output=process.stdout.decode("utf-8","replace").strip()
    rows=[]
    for line in output.splitlines():
        fields=line.split("|")
        if len(fields)!=4:
            raise Blocked("XTDB_UNEXPECTED_QUERY_FIELDS")
        rows.append(tuple(fields))
    if len(rows)>16:
        raise Blocked("XTDB_QUERY_ROW_COUNT_BOUND")
    return rows

def query(mod,network:str,host:str,tenant:str,valid_at:str,known_at:str)->dict:
    """Two native original XTDB filtered SELECTs + deterministic source-ID join.

    The original single XTDB SQL JOIN has a preserved RED planning witness;
    this intentionally qualifies a narrower application-level reconciliation
    path. NEVER report it as native SQL JOIN or XTDB system-time parity.
    """
    for moment in (valid_at,known_at):
        if not re.fullmatch(
            r"20[0-9]{2}-[01][0-9]-[0-3][0-9]T[0-2][0-9]:[0-5][0-9]:[0-5][0-9]Z",
            moment):
            raise Blocked("UNREVIEWED_QUERY_CLOCK")
    if tenant not in ("alpha","beta"):
        raise Blocked("UNREVIEWED_TENANT")
    sql_sources=(
        "SELECT _id,lineage_id,tenant,acquired_at FROM mail_source_r3 "
        "WHERE tenant="+quote(tenant)+" AND acquired_at<="+quote(known_at)+";"
    )
    sql_claims=(
        "SELECT _id,source_id,polarity,valid_from FROM mail_claim_r3 "
        "WHERE tenant="+quote(tenant)+" AND proposition='coast.approved' "
        "AND modality='actual' AND valid_from<="+quote(valid_at)+
        " AND observed_at<="+quote(known_at)+";"
    )
    try:
        source_rows=xtdb_rows(mod,network,host,sql_sources)
    except ValueError as exc:
        raise Blocked("SOURCE_FILTER_"+str(exc)) from exc
    try:
        claim_rows=xtdb_rows(mod,network,host,sql_claims)
    except ValueError as exc:
        raise Blocked("CLAIM_FILTER_"+str(exc)) from exc
    sources={}
    for source_id,lineage,source_tenant,acquired in source_rows:
        if (source_id in sources or source_tenant!=tenant or
                acquired>known_at or not lineage):
            raise Blocked("SOURCE_VIEW_OR_ACQUISITION_INVALID")
        sources[source_id]=lineage
    source_ids=set()
    positive=set()
    negative=set()
    for claim_id,source_id,polarity,claim_valid in claim_rows:
        if not claim_id or claim_valid>valid_at:
            raise Blocked("CLAIM_VIEW_OR_VALID_TIME_INVALID")
        lineage=sources.get(source_id)
        if lineage is None:
            # A valid, recorded claim may refer to a source not yet acquired
            # for the requested knowledge cutoff. Never infer source deletion.
            continue
        if source_id in source_ids:
            raise Blocked("DUPLICATE_CLAIM_OR_ID_COLLISION")
        source_ids.add(source_id)
        if polarity=="1":
            positive.add(lineage)
        elif polarity=="-1":
            negative.add(lineage)
        else:
            raise Blocked("POLARITY_UNREVIEWED")
    return {
        "status":("BOTH" if positive and negative else
                  "SUPPORTED" if positive else
                  "REFUTED" if negative else "NEITHER"),
        "source_ids":sorted(source_ids),
        "support_lineages":len(positive),
        "refute_lineages":len(negative)
    }


def qualify()->dict:
    original=load_original()
    sources,claims,digest=baseline_source()
    started=time.monotonic()
    suffix=secrets.token_hex(4)
    name="mail-xtdb-r3-"+suffix
    network=name+"-net"
    volume=name+"-vol"
    made_network=made_volume=running=False
    original.docker("pull",original.ENGINE,timeout=105)
    original.docker("pull",original.CLIENT,timeout=90)
    try:
        original.docker("network","create","--internal",network,timeout=15)
        made_network=True
        original.docker("volume","create",volume,timeout=10)
        made_volume=True
        original.start(name,network,volume)
        running=True
        original.require_query(network,name,"SELECT 1;","1","PGWIRE_READY")
        for row in sources:
            _id,archive,locator,tenant,msgid,source_time,acquired,lineage,raw=row
            record=(_id,archive,locator,tenant,msgid,source_time,acquired,
                    lineage,raw,digest(raw))
            try:
                write_original(original,network,name,"mail_source_r3",
                    ("_id","archive_id","native_locator","tenant","message_id",
                     "source_time","acquired_at","lineage_id","raw_text",
                     "source_sha256"),[record])
            except ValueError as exc:
                raise Blocked("SOURCE_INSERT_"+_id.upper()+"_"+str(exc)) from exc
        for row in claims:
            _id,source_id,tenant,prop,polarity,modality,vfrom,vto,observed,excerpt=row
            try:
                write_original(original,network,name,"mail_claim_r3",
                    ("_id","source_id","tenant","proposition","polarity",
                     "modality","valid_from","valid_to","observed_at","excerpt"),[row])
            except ValueError as exc:
                raise Blocked("CLAIM_INSERT_"+_id.upper()+"_"+str(exc)) from exc
        original.require_query(network,name,"SELECT COUNT(*) FROM mail_source_r3;",
                               "6","ALL_SOURCE_OCCURRENCES")
        original.require_query(network,name,"SELECT COUNT(*) FROM mail_claim_r3;",
                               "6","ALL_CLAIM_OCCURRENCES")
        successes={}
        for label,tenant,valid,known,expected_status,expected_sources in GOLD:
            try:
                observed=query(original,network,name,tenant,valid,known)
            except ValueError as exc:
                raise Blocked("CASE_"+label.upper()+"_"+str(exc)) from exc
            if observed["status"]!=expected_status or observed["source_ids"]!=list(expected_sources):
                raise Blocked("EIGHT_CASE_SOURCE_OR_STATUS_"+label.upper())
            successes[label]=observed
        if successes["late_reacquisition"]["refute_lineages"]!=1 or (
            successes["late_reacquisition"]["source_ids"]!=["a1","a2","a4"]
        ):
            raise Blocked("REACQUIRED_COPY_AS_EXTRA_VOTE")
        if ("a5" in successes["late_reacquisition"]["source_ids"] or
            "beta1" in successes["later_known"]["source_ids"]):
            raise Blocked("PLANNED_OR_CROSS_TENANT_LEAK")
        original.docker("stop","--time","8",name,timeout=22)
        original.docker("rm",name,timeout=12)
        running=False
        original.start(name,network,volume)
        running=True
        after=query(original,network,name,"alpha",
                    "2026-05-03T12:00:00Z","2026-05-11T00:00:00Z")
        if after!=successes["late_retro"]:
            raise Blocked("RESTART_EIGHT_CASE_DRIFT")
        original.require_query(network,name,"SELECT COUNT(*) FROM mail_source_r3;",
                               "6","RESTART_SOURCE_COUNT")
        elapsed=round(time.monotonic()-started,2)
        return {
            "schema":SCHEMA,
            "classification":"ORIGINAL_XTDB_TWO_QUERY_APP_JOIN_TEMPORAL_GOLD",
            "engine_digest":original.XTDB_DIGEST,
            "client_digest":original.CLIENT.rsplit("@sha256:",1)[-1],
            "same_frozen_eight_cases_verified":True,
            "xtdb_native_sql_join_verified":False,
            "adapter_source_join_verified":True,
            "case_count":len(GOLD),
            "source_occurrences":len(sources),
            "claim_occurrences":len(claims),
            "cross_tenant_query_filtered":True,
            "original_records_preserved":True,
            "reacquired_lineage_not_extra_vote":True,
            "planned_not_completed":True,
            "restart_verified":True,
            "xtdb_native_system_time_parity":False,
            "xtdb_source_immutability_enforced":False,
            "model_inference":False,
            "native_pst_qualified":False,
            "fixture_sha256":digest(json.dumps(sources,ensure_ascii=False)),
            "elapsed_seconds":elapsed,
            "source_history_risk":"XTDB_UPSERT_ID_REQUIRES_APPLICATION_GUARD",
        }
    finally:
        if running:
            try:original.docker("rm","-f",name,timeout=15)
            except (OSError,original.Blocked):pass
        if made_volume:
            try:original.docker("volume","rm","-f",volume,timeout=15)
            except (OSError,original.Blocked):pass
        if made_network:
            try:original.docker("network","rm",network,timeout=15)
            except (OSError,original.Blocked):pass

if __name__=="__main__":
    try:
        print(json.dumps(qualify(),sort_keys=True,separators=(",",":")))
    except (Blocked,OSError,ValueError,IndexError,subprocess.TimeoutExpired) as exc:
        # Original XTDB adapter's fixed Blocked extends ValueError but is
        # deliberately defined in a different module; retain its sanitized
        # failure class rather than discarding it as generic I/O.
        details=str(exc) if isinstance(exc,ValueError) else "XTDB_R3_UNCLASSIFIED_IO"
        print("XTDB_R3_FIRST_FAILURE="+re.sub(r"[^A-Z0-9_]","_",details.upper())[:90],
              file=sys.stderr)
        raise SystemExit(2)
