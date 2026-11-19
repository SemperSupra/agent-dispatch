#!/usr/bin/env python3
"""Public-only, real PostgreSQL 18 temporal and restart bakeoff.

Uses official Docker Postgres 18.3, no published ports and --network none.
A model/source fact is never rewritten to "fix" a later contradiction.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import time

SCHEMA="mail-public-postgres18-temporal-v1"
IMAGE="postgres:18.3"
MAX_OUTPUT=32768
SQL_SCHEMA=r"""
CREATE TABLE source_occurrence (
  id text PRIMARY KEY,
  tenant text NOT NULL,
  archive_id text NOT NULL,
  native_locator text NOT NULL,
  lineage_id text NOT NULL,
  source_time timestamptz NOT NULL,
  acquired_at timestamptz NOT NULL,
  original_text text NOT NULL,
  source_sha256 text NOT NULL,
  UNIQUE (archive_id, native_locator)
);
CREATE TABLE assertion (
  id text PRIMARY KEY,
  source_id text NOT NULL REFERENCES source_occurrence(id),
  tenant text NOT NULL,
  proposition text NOT NULL,
  polarity smallint NOT NULL CHECK (polarity IN (-1,1)),
  modality text NOT NULL CHECK (modality IN ('actual','planned')),
  valid_period tstzrange NOT NULL CHECK (NOT isempty(valid_period)),
  observed_at timestamptz NOT NULL,
  quote text NOT NULL
);
CREATE INDEX temporal_lookup
ON assertion (tenant,proposition,modality,observed_at);
CREATE INDEX valid_period_index ON assertion USING GIST(valid_period);
-- The text portion of PostgreSQL 18 temporal unique GiST needs btree_gist.
CREATE EXTENSION IF NOT EXISTS btree_gist;
-- Native PostgreSQL 18 declarative WITHOUT OVERLAPS is used ONLY on
-- versioned policy intervals, NEVER on contradictory source assertions.
CREATE TABLE approved_policy_window (
  policy_id text NOT NULL,
  valid_period tstzrange NOT NULL,
  UNIQUE (policy_id, valid_period WITHOUT OVERLAPS)
);
CREATE TABLE assessment_history (
 id text PRIMARY KEY,
 tenant text NOT NULL,
 proposition text NOT NULL,
 valid_at timestamptz NOT NULL,
 known_at timestamptz NOT NULL,
 verdict text NOT NULL CHECK (verdict IN ('NEITHER','SUPPORTED','REFUTED','BOTH')),
 source_ids text NOT NULL
);
CREATE FUNCTION reject_source_mutation() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN RAISE EXCEPTION 'SOURCE_AND_ASSESSMENT_IMMUTABLE'; END
$$;
CREATE TRIGGER immutable_source BEFORE UPDATE OR DELETE ON source_occurrence
 FOR EACH ROW EXECUTE FUNCTION reject_source_mutation();
CREATE TRIGGER immutable_assertion BEFORE UPDATE OR DELETE ON assertion
 FOR EACH ROW EXECUTE FUNCTION reject_source_mutation();
CREATE TRIGGER immutable_assessment BEFORE UPDATE OR DELETE ON assessment_history
 FOR EACH ROW EXECUTE FUNCTION reject_source_mutation();
CREATE FUNCTION assert_tenant_match() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
 IF (SELECT tenant FROM source_occurrence WHERE id=NEW.source_id) <> NEW.tenant THEN
 RAISE EXCEPTION 'SOURCE_TENANT_MISMATCH'; END IF;
 RETURN NEW;
END $$;
CREATE TRIGGER tenancy BEFORE INSERT ON assertion
 FOR EACH ROW EXECUTE FUNCTION assert_tenant_match();
"""
SOURCES=[
 ("a1","alpha","export-a","f1/item1","original-denial","2026-05-02T08:00:00Z","2026-05-02T09:00:00Z","Approval denied."),
 ("a2","alpha","export-a","f1/item2","approval-revision","2026-05-05T08:00:00Z","2026-05-05T09:00:00Z","Approval granted effective May 4."),
 ("a3","alpha","export-c","f7/item9","retroactive-approval","2026-05-03T12:00:00Z","2026-05-10T09:00:00Z","Approval effective May 3 discovered later."),
 ("a4","alpha","export-b","f9/item7","original-denial","2026-05-02T08:00:00Z","2026-05-06T09:00:00Z","Approval denied."),
 ("a5","alpha","export-a","f1/item5","future-plan","2026-05-02T07:00:00Z","2026-05-02T07:20:00Z","Approval will be granted next week."),
 ("beta1","beta","export-private","f1/item1","beta-only","2026-05-01T07:00:00Z","2026-05-01T08:00:00Z","Private tenant approved."),
]
CLAIMS=[
 ("c1","a1","alpha","approved",-1,"actual","2026-05-02T00:00:00Z","2026-05-02T09:00:00Z","Approval denied."),
 ("c2","a2","alpha","approved",1,"actual","2026-05-04T00:00:00Z","2026-05-05T09:00:00Z","Approval granted"),
 ("c3","a3","alpha","approved",1,"actual","2026-05-03T00:00:00Z","2026-05-10T09:00:00Z","Approval effective"),
 ("c4","a4","alpha","approved",-1,"actual","2026-05-02T00:00:00Z","2026-05-06T09:00:00Z","Approval denied."),
 ("c5","a5","alpha","approved",1,"planned","2026-05-09T00:00:00Z","2026-05-02T07:20:00Z","Approval will be granted"),
 ("c6","beta1","beta","approved",1,"actual","2026-05-01T00:00:00Z","2026-05-01T08:00:00Z","Private tenant approved."),
]
CASES=[
 ("before_any","alpha","2026-05-01T12:00:00Z","2026-05-11T00:00:00Z"),
 ("early_known","alpha","2026-05-03T12:00:00Z","2026-05-04T00:00:00Z"),
 ("late_retro","alpha","2026-05-03T12:00:00Z","2026-05-11T00:00:00Z"),
 ("pre_arrival","alpha","2026-05-04T12:00:00Z","2026-05-04T12:00:00Z"),
 ("later_known","alpha","2026-05-04T12:00:00Z","2026-05-06T00:00:00Z"),
 ("late_reacquisition","alpha","2026-05-04T12:00:00Z","2026-05-07T00:00:00Z"),
 ("beta_private","beta","2026-05-03T12:00:00Z","2026-05-11T00:00:00Z"),
 ("alpha_unknown","alpha","2026-05-01T12:00:00Z","2026-05-02T08:00:00Z"),
]
QUERY=r"""
SELECT c.polarity, s.id, s.lineage_id
FROM assertion c
JOIN source_occurrence s ON s.id=c.source_id
WHERE c.tenant='TENANT' AND s.tenant='TENANT'
AND c.proposition='approved' AND c.modality='actual'
AND c.valid_period @> TIMESTAMPTZ 'VALID'
AND c.observed_at <= TIMESTAMPTZ 'KNOWN'
AND s.acquired_at <= TIMESTAMPTZ 'KNOWN'
ORDER BY s.id,c.id;
"""

def run(argv, *, input_text=None, timeout=35, check=True):
    cp=subprocess.run(argv,input=input_text,stdout=subprocess.PIPE,stderr=subprocess.PIPE,
                      text=True,timeout=timeout,check=False,env={
                          "HOME":os.environ.get("HOME","/tmp"),
                          "PATH":os.environ.get("PATH","/usr/bin:/bin"),
                          "LANG":"C.UTF-8",
                          "DOCKER_CONFIG":os.environ.get("DOCKER_CONFIG",os.path.join("/tmp","public-mail-docker")),
                      })
    if len(cp.stdout)>MAX_OUTPUT or len(cp.stderr)>MAX_OUTPUT:
        raise ValueError("UNBOUNDED_POSTGRES_OUTPUT")
    if check and cp.returncode:
        sqlstate=re.search(r"[0-9A-Z]{5}",cp.stderr)
        code=sqlstate.group(0) if sqlstate else "NO_SQLSTATE"
        # No real data or secrets are used by this isolated fixture.
        # This bounded SQL engine message permits precise correction without
        # granting a retry with arbitrary SQL/network privileges.
        safe=re.sub(r"[^a-zA-Z0-9 _:.()-]","_",cp.stderr[:160])
        raise ValueError("NATIVE_POSTGRES_COMMAND_FAILED_"+code+"_"+safe)
    return cp

def pg(name,sql,*,expect_error=False):
    p=run(["docker","exec","-i",name,"psql","-X","-v","ON_ERROR_STOP=1","-v","VERBOSITY=sqlstate",
           "-U","postgres","-d","mail_public","-t","-A","-F","|"],
          input_text=sql,timeout=35,check=not expect_error)
    if expect_error and p.returncode==0:
        raise ValueError("EXPECTED_POSTGRES_REJECTION_MISSING")
    return p.stdout.strip()

def sql_string(x):
    return "'"+str(x).replace("'","''")+"'"

def setup(name):
    sources=[]
    for id,tenant,archive,locator,lineage,authored,acquired,raw in SOURCES:
        row=(id,tenant,archive,locator,lineage,authored,acquired,raw,
             hashlib.sha256(raw.encode()).hexdigest())
        sources.append("("+",".join(sql_string(x) for x in row)+")")
    claims=[]
    for id,source,tenant,proposition,polarity,modality,effective,observed,quote in CLAIMS:
        vals=[id,source,tenant,proposition,polarity,modality,effective,observed,quote]
        claims.append("("+",".join(str(v) if isinstance(v,int) else sql_string(v) for v in vals)+")")
    insert_sources="INSERT INTO source_occurrence VALUES "+",".join(sources)+";"
    insert_claims=(
      "INSERT INTO assertion (id,source_id,tenant,proposition,polarity,modality,valid_period,observed_at,quote) "
      "VALUES "+",".join(
        "("+",".join([sql_string(v[0]),sql_string(v[1]),sql_string(v[2]),
                          sql_string(v[3]),str(v[4]),sql_string(v[5]),
                          "tstzrange("+sql_string(v[6])+",NULL,'[)')",
                          sql_string(v[7]),sql_string(v[8])])+")"
        for v in CLAIMS)+";")
    for stage,script in (("SCHEMA",SQL_SCHEMA),
                         ("SOURCE_INSERT",insert_sources),
                         ("CLAIM_INSERT",insert_claims)):
        try: pg(name,script)
        except ValueError as exc:
            raise ValueError("PG18_"+stage+"_"+str(exc)) from exc
    if pg(name,"SELECT current_setting('server_version_num');").splitlines()[0][:2]!="18":
        raise ValueError("NOT_NATIVE_POSTGRES18")

def query(name,tenant,valid,known):
    sql=QUERY.replace("TENANT",tenant).replace("VALID",valid).replace("KNOWN",known)
    raw=pg(name,sql)
    positive=set()
    negative=set()
    refs=[]
    if raw:
        for line in raw.splitlines():
            polarity,source,lineage=line.split("|")
            refs.append(source)
            (positive if polarity=="1" else negative).add(lineage)
    state=("BOTH" if positive and negative else "SUPPORTED" if positive
           else "REFUTED" if negative else "NEITHER")
    return {"status":state,"sources":sorted(refs),
            "support_lineages":len(positive),"refute_lineages":len(negative)}

def qualify():
    name="mail-temporal-pg18-"+re.sub("[^a-z0-9]","",os.getenv("GITHUB_RUN_ID","local"))[-16:]
    started=time.monotonic()
    image=IMAGE
    try:
        run(["docker","pull",image],timeout=180)
        image_id=run(["docker","image","inspect","--format","{{.Id}}",image]).stdout.strip()
        if not re.fullmatch(r"sha256:[0-9a-f]{64}",image_id):
            raise ValueError("IMAGE_DIGEST_INVALID")
        run(["docker","run","--detach","--name",name,"--network","none",
             "--env","POSTGRES_HOST_AUTH_METHOD=trust",
             "--env","POSTGRES_DB=mail_public",image],timeout=60)
        for attempt in range(35):
            if run(["docker","exec",name,"pg_isready","-U","postgres","-d","mail_public"],
                   check=False,timeout=8).returncode==0:break
            time.sleep(1)
        else:raise ValueError("POSTGRES_START_TIMEOUT")
        setup(name)
        observations={k:query(name,tenant,valid,known)
                      for k,tenant,valid,known in CASES}
        if pg(name,"SELECT count(*) FROM source_occurrence;")!="6" or            pg(name,"SELECT count(*) FROM assertion;")!="6":
            raise ValueError("SOURCE_OR_CLAIM_LOSS")
        if observations["late_reacquisition"]["refute_lineages"]!=1 or            len(observations["late_reacquisition"]["sources"])!=3:
            raise ValueError("DUPLICATE_ORIGINAL_REACQUISITION_VOTE")
        pg(name,"INSERT INTO approved_policy_window VALUES "
           "('review',tstzrange('2026-05-01','2026-06-01','[)'));")
        pg(name,"INSERT INTO approved_policy_window VALUES "
           "('review',tstzrange('2026-05-15','2026-06-15','[)'));",expect_error=True)
        pg(name,"UPDATE source_occurrence SET original_text='changed' WHERE id='a1';",expect_error=True)
        pg(name,"DELETE FROM assertion WHERE id='c1';",expect_error=True)
        pg(name,"INSERT INTO assertion VALUES ('bad','beta1','alpha','approved',1,"
           "'actual',tstzrange('2026-05-01',NULL,'[)'),"
           "'2026-05-01','bad');",expect_error=True)
        for id in ("early_known","late_retro"):
            _,tenant,valid,known=next(c for c in CASES if c[0]==id)
            value=observations[id]
            pg(name,"INSERT INTO assessment_history VALUES ("+
               ",".join(sql_string(v) for v in (
                   id,tenant,"approved",valid,known,value["status"],
                   json.dumps(value["sources"],sort_keys=True)))+");")
        run(["docker","stop","--time","5",name],timeout=35)
        run(["docker","start",name],timeout=25)
        for attempt in range(30):
            if run(["docker","exec",name,"pg_isready","-U","postgres","-d","mail_public"],
                   check=False,timeout=8).returncode==0:break
            time.sleep(1)
        else:raise ValueError("POSTGRES_RESTART_TIMEOUT")
        for id in ("early_known","late_retro"):
            _,tenant,valid,known=next(c for c in CASES if c[0]==id)
            if query(name,tenant,valid,known)!=observations[id]:
                raise ValueError("RESTART_CORRUPTS_ASOF_RESULT")
        if pg(name,"SELECT count(*) FROM assessment_history;")!="2":
            raise ValueError("HISTORY_DISAPPEARED_ON_RESTART")
        pg(name,"DELETE FROM assessment_history WHERE id='early_known';",expect_error=True)
        return {"schema":SCHEMA,"classification":"REAL_POSTGRES18_TEMPORAL_SQL_PROJECTION",
                "engine":"PostgreSQL 18","image_id":image_id,"image_tag":IMAGE,
                "image_digest_pinned":False,"version_locked":False,
                "source_occurrences":6,"claim_observations":6,
                "case_count":len(CASES),"results":observations,
                "native_without_overlaps_verified":True,
                "source_immutability_verified":True,
                "source_tenant_constraint_verified":True,
                "replay_restart_verified":True,
                "model_inference":False,"real_mail":False,
                "elapsed_seconds":round(time.monotonic()-started,2)}
    finally:
        run(["docker","rm","--force",name],check=False,timeout=30)

if __name__=="__main__":
    a=argparse.ArgumentParser()
    a.add_argument("--out",required=True)
    args=a.parse_args()
    result=qualify()
    out=Path(args.out);out.parent.mkdir(parents=True,exist_ok=True)
    out.write_text(json.dumps(result,sort_keys=True,separators=(",",":"))+"\n",encoding="utf-8")
    print("POSTGRES18_TEMPORAL_NATIVE_EXECUTED=TRUE")
