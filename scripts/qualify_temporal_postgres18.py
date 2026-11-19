#!/usr/bin/env python3
"""Actual pinned PostgreSQL 18 in isolated disposable Docker, no private mail.

Uses SAME fictional source and claim fixture rows as native SQLite R1. Executes
SQL inside the real PostgreSQL server via UNIX socket: no published network
ports, no model API, no permanent service or credentials.
"""
from __future__ import annotations

import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import secrets
import subprocess
import sys
import time

ROOT=Path(__file__).resolve().parents[1]
SQLITE_FIXTURE=ROOT/"tools/mail-evidence-challenge/temporal_sqlite/qualify.py"
IMAGE="postgres:18.7-trixie@sha256:e754b839f447639b7004895f4d8a4bfcb4e9dbe3a1bc035f27f646562a16fd61"
SCHEMA="mail-temporal-native-postgresql18-r2"
MAX_SECONDS=190

class Blocked(ValueError): pass

def run(argv:list[str], timeout:int, data:bytes|None=None)->subprocess.CompletedProcess[bytes]:
    try:
        result=subprocess.run(argv,stdin=subprocess.PIPE if data is not None else subprocess.DEVNULL,
            input=data,stdout=subprocess.PIPE,stderr=subprocess.PIPE,
            timeout=timeout,check=False)
    except subprocess.TimeoutExpired as exc:
        raise Blocked("NATIVE_POSTGRES_TIMEOUT_"+Path(argv[0]).name) from exc
    if result.returncode:
        raise Blocked("NATIVE_POSTGRES_NONZERO_"+Path(argv[0]).name+"_"+str(result.returncode))
    if len(result.stdout)>65536 or len(result.stderr)>65536:
        raise Blocked("POSTGRES_UNBOUNDED_OUTPUT")
    return result

def docker(*args:str,timeout:int=25)->str:
    return run(["docker",*args],timeout).stdout.decode("utf-8","replace").strip()

def quote(value)->str:
    return "NULL" if value is None else "'"+str(value).replace("'","''")+"'"

def original_fixture()->tuple:
    spec=importlib.util.spec_from_file_location("mail_temporal_sqlite_public_r1",SQLITE_FIXTURE)
    if spec is None or spec.loader is None:raise Blocked("SQLITE_BASELINE_MISSING")
    module=importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module.SOURCE_ROWS,module.CLAIM_ROWS,module.digest

DDL="""
CREATE EXTENSION IF NOT EXISTS btree_gist;
CREATE TABLE source_occurrence (
 id text PRIMARY KEY,
 archive_id text NOT NULL,
 native_locator text NOT NULL,
 tenant text NOT NULL,
 message_id text,
 source_time timestamptz NOT NULL,
 acquired_at timestamptz NOT NULL,
 lineage_id text NOT NULL,
 original_text text NOT NULL,
 source_sha256 text NOT NULL,
 UNIQUE(archive_id,native_locator)
);
CREATE TABLE claim_observation (
 id text PRIMARY KEY,
 source_id text NOT NULL REFERENCES source_occurrence(id),
 tenant text NOT NULL,
 proposition text NOT NULL,
 polarity integer NOT NULL CHECK(polarity IN(-1,1)),
 modality text NOT NULL CHECK(modality IN('actual','planned')),
 valid_from timestamptz NOT NULL,
 valid_to timestamptz,
 observed_at timestamptz NOT NULL,
 excerpt text NOT NULL,
 CHECK(valid_to IS NULL OR valid_to>valid_from)
);
CREATE INDEX claim_lookup ON claim_observation (tenant,proposition,valid_from,observed_at);
CREATE TABLE derived_valid_period (
 source_id text NOT NULL REFERENCES source_occurrence(id),
 valid_window tstzrange NOT NULL,
 PRIMARY KEY (source_id, valid_window WITHOUT OVERLAPS)
);
CREATE TABLE assessment_history (
 id text PRIMARY KEY, tenant text NOT NULL, proposition text NOT NULL,
 valid_at timestamptz NOT NULL, known_at timestamptz NOT NULL,
 verdict text NOT NULL CHECK (verdict IN ('NEITHER','SUPPORTED','REFUTED','BOTH')),
 policy_sha256 text NOT NULL
);
CREATE FUNCTION protect_immutable() RETURNS trigger AS $immutable$
BEGIN RAISE EXCEPTION 'ORIGINAL_SOURCE_AND_ASSESSMENT_IMMUTABLE';
END $immutable$ LANGUAGE plpgsql;
CREATE TRIGGER protect_source BEFORE UPDATE OR DELETE ON source_occurrence
 FOR EACH ROW EXECUTE FUNCTION protect_immutable();
CREATE TRIGGER protect_claim BEFORE UPDATE OR DELETE ON claim_observation
 FOR EACH ROW EXECUTE FUNCTION protect_immutable();
CREATE TRIGGER protect_assessment BEFORE UPDATE OR DELETE ON assessment_history
 FOR EACH ROW EXECUTE FUNCTION protect_immutable();
CREATE FUNCTION protect_tenant() RETURNS trigger AS $tenant$
BEGIN
 IF (SELECT tenant FROM source_occurrence WHERE id=NEW.source_id) IS DISTINCT FROM NEW.tenant THEN
  RAISE EXCEPTION 'CROSS_TENANT_CLAIM';
 END IF;
 RETURN NEW;
END $tenant$ LANGUAGE plpgsql;
CREATE TRIGGER claim_tenant_gate BEFORE INSERT ON claim_observation
 FOR EACH ROW EXECUTE FUNCTION protect_tenant();
"""

def sql(container:str,statement:str,*,must_pass=True)->str:
    p=subprocess.run(
        ["docker","exec","-i",container,"psql","-U","postgres","-d","postgres",
         "-q","-X","-A","-t","-v","ON_ERROR_STOP=1","-f","-"],
        input=statement.encode(),stdout=subprocess.PIPE,stderr=subprocess.PIPE,
        timeout=40,check=False)
    if len(p.stdout)>65536 or len(p.stderr)>65536:raise Blocked("POSTGRES_SQL_OUTPUT_BOUND")
    if must_pass and p.returncode:
        raise Blocked("POSTGRES_SQL_EXECUTION_FAILED")
    if not must_pass and p.returncode==0:
        raise Blocked("POSTGRES_NEGATIVE_MUTATION_ACCEPTED")
    return p.stdout.decode("utf-8","replace").strip()

def start_container(name:str,volume:str)->None:
    docker("run","-d","--name",name,
           "--network","none","--pids-limit","256","--cpus","2",
           "--memory","1024m","--memory-swap","1024m",
           "--mount","type=volume,src="+volume+",dst=/var/lib/postgresql",
           "--env","POSTGRES_HOST_AUTH_METHOD=trust",
           "--env","PGTZ=UTC",IMAGE,timeout=65)
    for _ in range(35):
        result=subprocess.run(["docker","exec",name,"pg_isready","-q","-U","postgres"],
                              stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,
                              timeout=3,check=False)
        if result.returncode==0:return
        time.sleep(1)
    raise Blocked("POSTGRES_NOT_READY")

def query(container:str,tenant:str,valid:str,known:str)->dict:
    # Parameters are exclusively from the fixed reviewer-controlled test list.
    sqltext=f"""
WITH visible AS (
 SELECT s.id AS source_id,s.lineage_id,c.polarity
 FROM claim_observation c JOIN source_occurrence s ON s.id=c.source_id
 WHERE c.tenant={quote(tenant)} AND s.tenant={quote(tenant)}
   AND c.proposition='coast.approved' AND c.modality='actual'
   AND c.valid_from <= {quote(valid)}::timestamptz
   AND (c.valid_to IS NULL OR {quote(valid)}::timestamptz<c.valid_to)
   AND c.observed_at <= {quote(known)}::timestamptz
   AND s.acquired_at <= {quote(known)}::timestamptz
), counts AS (
 SELECT COUNT(DISTINCT lineage_id) FILTER (WHERE polarity=1) AS supported,
        COUNT(DISTINCT lineage_id) FILTER (WHERE polarity=-1) AS refuted,
        COUNT(DISTINCT source_id) AS occurrences FROM visible
)
SELECT json_build_object(
 'supported',counts.supported, 'refuted',counts.refuted,
 'occurrences',counts.occurrences,
 'status',CASE WHEN counts.supported>0 AND counts.refuted>0 THEN 'BOTH'
               WHEN counts.supported>0 THEN 'SUPPORTED'
               WHEN counts.refuted>0 THEN 'REFUTED'
               ELSE 'NEITHER' END
)::text FROM counts;
"""
    return json.loads(sql(container,sqltext).splitlines()[-1])

def qualify()->dict:
    if sys.platform!="linux":raise Blocked("POSTGRES_LINUX_ONLY")
    source,claims,digest=original_fixture()
    name="mail-pg-r2-"+secrets.token_hex(5)
    volume="mail-pg-r2-volume-"+secrets.token_hex(5)
    started=time.monotonic()
    docker("pull",IMAGE,timeout=100)
    docker("volume","create",volume,timeout=10)
    has_container=False
    try:
        start_container(name,volume)
        has_container=True
        version=sql(name,"SHOW server_version;").splitlines()[-1]
        if not version.startswith("18.7"):raise Blocked("POSTGRES_MAJOR_MINOR_DRIFT")
        sql(name,DDL)
        for row in source:
            fields=(*row,digest(row[-1]))
            sql(name,"INSERT INTO source_occurrence VALUES ("+",".join(quote(x) for x in fields)+");")
        for row in claims:
            sql(name,"INSERT INTO claim_observation VALUES ("+",".join(quote(x) for x in row)+");")
        if int(sql(name,"SELECT COUNT(*) FROM source_occurrence;").splitlines()[-1])!=len(source):
            raise Blocked("SOURCE_OCCURRENCE_DROP")
        if int(sql(name,"SELECT COUNT(*) FROM claim_observation;").splitlines()[-1])!=len(claims):
            raise Blocked("CLAIM_DROP")
        cases=[
            ("before_any","alpha","2026-05-01T12:00:00Z","2026-05-11T00:00:00Z","NEITHER",0),
            ("early_known","alpha","2026-05-03T12:00:00Z","2026-05-04T00:00:00Z","REFUTED",1),
            ("late_retro","alpha","2026-05-03T12:00:00Z","2026-05-11T00:00:00Z","BOTH",3),
            ("pre_arrival","alpha","2026-05-04T12:00:00Z","2026-05-04T12:00:00Z","REFUTED",1),
            ("later_known","alpha","2026-05-04T12:00:00Z","2026-05-06T00:00:00Z","BOTH",2),
            ("late_copy","alpha","2026-05-04T12:00:00Z","2026-05-07T00:00:00Z","BOTH",3),
            ("beta_private","beta","2026-05-03T12:00:00Z","2026-05-11T00:00:00Z","SUPPORTED",1),
            ("alpha_unknown","alpha","2026-05-01T12:00:00Z","2026-05-02T08:00:00Z","NEITHER",0),
        ]
        observed={}
        for label,tenant,valid,known,status,qty in cases:
            r=query(name,tenant,valid,known)
            if r["status"]!=status or r["occurrences"]!=qty:
                raise Blocked("SQL_POSTGRES_TIME_GOLD_"+label)
            observed[label]=r
        if observed["late_copy"]["refuted"]!=1 or observed["late_copy"]["occurrences"]!=3:
            raise Blocked("PG_DUPLICATE_VOTES")
        # Explicit PostgreSQL 18 WITHOUT OVERLAPS applies per *source*
        # validity, never across different sources asserting contradictory facts.
        sql(name,"INSERT INTO derived_valid_period VALUES ('a1','[2026-05-01,2026-05-05)'::tstzrange);")
        sql(name,"INSERT INTO derived_valid_period VALUES ('a1','[2026-05-05,2026-05-09)'::tstzrange);")
        sql(name,"INSERT INTO derived_valid_period VALUES ('a2','[2026-05-02,2026-05-08)'::tstzrange);")
        sql(name,"INSERT INTO derived_valid_period VALUES ('a1','[2026-05-03,2026-05-07)'::tstzrange);",
            must_pass=False)
        sql(name,"DELETE FROM source_occurrence WHERE id='a1';",must_pass=False)
        sql(name,"UPDATE source_occurrence SET original_text='changed' WHERE id='a1';",must_pass=False)
        sql(name,"UPDATE claim_observation SET excerpt='forged' WHERE id='claim-denied';",
            must_pass=False)
        sql(name,("INSERT INTO claim_observation VALUES "
            "('forgery','beta1','alpha','coast.approved',1,'actual',"
            "'2026-05-01T00:00:00Z',NULL,'2026-05-01T08:00:00Z','fake');"),must_pass=False)
        sql(name,("INSERT INTO assessment_history VALUES "
            "('known-earlier','alpha','coast.approved','2026-05-03T12:00:00Z',"
            "'2026-05-04T00:00:00Z','REFUTED','public-policy-r2');"))
        # Restart the same named volume with no published TCP port.
        docker("stop","--time","5",name,timeout=15)
        docker("rm",name,timeout=10)
        has_container=False
        start_container(name,volume)
        has_container=True
        if query(name,"alpha","2026-05-03T12:00:00Z",
                 "2026-05-11T00:00:00Z")!=observed["late_retro"]:
            raise Blocked("POSTGRES_RESTART_REPLAY_DRIFT")
        if sql(name,"SELECT verdict FROM assessment_history WHERE id='known-earlier';").strip()!="REFUTED":
            raise Blocked("OLD_ASSESSMENT_CHANGED")
        sql(name,"UPDATE assessment_history SET verdict='SUPPORTED' WHERE id='known-earlier';",
            must_pass=False)
        elapsed=round(time.monotonic()-started,2)
        return {"schema":SCHEMA,"classification":"NATIVE_POSTGRES18_TEMPORAL_ONLY",
            "postgres_version":version,
            "image_digest":IMAGE.rsplit("@sha256:",1)[-1],
            "image_immutable":True,
            "qualified_cases":len(cases),
            "source_occurrences":len(source),"claims":len(claims),
            "four_valued_source_support":True,
            "valid_at_and_known_at_separate":True,
            "overlap_constraint_qualified":True,
            "same_source_overlap_denied":True,
            "different_source_overlap_preserved":True,
            "cross_tenant_denied":True,
            "immutable_source_denied":True,
            "restart_verified":True,"local_only_no_published_ports":True,
            "model_inference":False,"native_pst_qualified":False,
            "fixture_sha256":digest(json.dumps(source,ensure_ascii=False)),
            "elapsed_seconds":elapsed}
    finally:
        if has_container:
            try:docker("rm","-f",name,timeout=15)
            except (OSError,Blocked):pass
        try:docker("volume","rm","-f",volume,timeout=15)
        except (OSError,Blocked):pass

if __name__=="__main__":
    try:
        print(json.dumps(qualify(),sort_keys=True,separators=(",",":")))
    except (OSError,Blocked,ValueError,subprocess.TimeoutExpired) as exc:
        msg=str(exc) if isinstance(exc,Blocked) else "PG_RUNTIME_IO"
        print("POSTGRES_FIRST_FAILURE="+re.sub("[^A-Z0-9_]","_",msg.upper())[:85],
              file=sys.stderr)
        raise SystemExit(2)
