#!/usr/bin/env python3
"""Actual SQLite bitemporal/contradiction witness, synthetic mail only.

A portable SQL experiment, not PST extraction, generic temporal database,
linguistic model, or determination of objective truth. Standard library only.
"""
from __future__ import annotations

import hashlib
import json
from pathlib import Path
import sqlite3
import tempfile

SCHEMA = "mail-temporal-sqlite-public-r1"
SQL = """
PRAGMA foreign_keys=ON;
CREATE TABLE source_occurrence (
 id TEXT PRIMARY KEY,
 archive_id TEXT NOT NULL,
 native_locator TEXT NOT NULL,
 tenant TEXT NOT NULL,
 message_id TEXT,
 source_time TEXT NOT NULL,
 acquired_at TEXT NOT NULL,
 lineage_id TEXT NOT NULL,
 original_text TEXT NOT NULL,
 source_sha256 TEXT NOT NULL,
 UNIQUE (archive_id,native_locator)
) STRICT;
CREATE TABLE claim_observation (
 id TEXT PRIMARY KEY,
 source_id TEXT NOT NULL REFERENCES source_occurrence(id),
 tenant TEXT NOT NULL,
 proposition TEXT NOT NULL,
 polarity INTEGER NOT NULL CHECK (polarity IN (-1,1)),
 modality TEXT NOT NULL CHECK (modality IN ('actual','planned')),
 valid_from TEXT NOT NULL,
 valid_to TEXT,
 observed_at TEXT NOT NULL,
 excerpt TEXT NOT NULL,
 CHECK (valid_to IS NULL OR valid_to > valid_from)
) STRICT;
CREATE TABLE assessment_history (
 id TEXT PRIMARY KEY,
 tenant TEXT NOT NULL,
 proposition TEXT NOT NULL,
 valid_at TEXT NOT NULL,
 known_at TEXT NOT NULL,
 verdict TEXT NOT NULL CHECK (verdict IN ('NEITHER','SUPPORTED','REFUTED','BOTH')),
 source_ids_json TEXT NOT NULL,
 policy_digest TEXT NOT NULL
) STRICT;
CREATE INDEX claim_lookup
 ON claim_observation(tenant,proposition,modality,valid_from,observed_at);
CREATE INDEX source_tenant_lineage
 ON source_occurrence(tenant,lineage_id,acquired_at);
CREATE INDEX assessment_by_cutoff
 ON assessment_history(tenant,proposition,known_at);
CREATE TRIGGER no_source_edit BEFORE UPDATE ON source_occurrence BEGIN
 SELECT RAISE(ABORT,'IMMUTABLE_SOURCE'); END;
CREATE TRIGGER no_source_delete BEFORE DELETE ON source_occurrence BEGIN
 SELECT RAISE(ABORT,'IMMUTABLE_SOURCE'); END;
CREATE TRIGGER no_claim_edit BEFORE UPDATE ON claim_observation BEGIN
 SELECT RAISE(ABORT,'IMMUTABLE_CLAIM'); END;
CREATE TRIGGER no_claim_delete BEFORE DELETE ON claim_observation BEGIN
 SELECT RAISE(ABORT,'IMMUTABLE_CLAIM'); END;
CREATE TRIGGER no_assessment_edit BEFORE UPDATE ON assessment_history BEGIN
 SELECT RAISE(ABORT,'IMMUTABLE_ASSESSMENT'); END;
CREATE TRIGGER no_assessment_delete BEFORE DELETE ON assessment_history BEGIN
 SELECT RAISE(ABORT,'IMMUTABLE_ASSESSMENT'); END;
CREATE TRIGGER claim_tenant_gate BEFORE INSERT ON claim_observation
 WHEN (SELECT tenant FROM source_occurrence WHERE id=NEW.source_id) != NEW.tenant
 BEGIN SELECT RAISE(ABORT,'CROSS_TENANT_SOURCE'); END;
"""
SOURCE_ROWS = [
    ("a1","export-a","f1/item1","alpha","<collision@invalid.test>","2026-05-02T08:00:00Z","2026-05-02T09:00:00Z","original-denial","Approval was denied."),
    ("a2","export-a","f1/item2","alpha","<collision@invalid.test>","2026-05-05T08:00:00Z","2026-05-05T09:00:00Z","approval-revised","Approval was granted, effective May 4."),
    ("a3","export-c","f7/item9","alpha","<retro@invalid.test>","2026-05-03T12:00:00Z","2026-05-10T09:00:00Z","retroactive-approval","Approval effective May 3, discovered late."),
    ("a4","export-b","f9/item7","alpha","<collision@invalid.test>","2026-05-02T08:00:00Z","2026-05-06T09:00:00Z","original-denial","Approval was denied."),
    ("a5","export-a","f1/item5","alpha",None,"2026-05-02T07:00:00Z","2026-05-02T07:20:00Z","future-plan","Approval will be granted next week."),
    ("beta1","export-private","f1/item1","beta","<private@invalid.test>","2026-05-01T07:00:00Z","2026-05-01T08:00:00Z","beta-only","Approval was granted in the private tenant."),
]
CLAIM_ROWS = [
    ("claim-denied","a1","alpha","coast.approved",-1,"actual","2026-05-02T00:00:00Z",None,"2026-05-02T09:00:00Z","Approval was denied."),
    ("claim-approved","a2","alpha","coast.approved",1,"actual","2026-05-04T00:00:00Z",None,"2026-05-05T09:00:00Z","Approval was granted"),
    ("claim-retro","a3","alpha","coast.approved",1,"actual","2026-05-03T00:00:00Z",None,"2026-05-10T09:00:00Z","Approval effective May 3"),
    ("claim-copy","a4","alpha","coast.approved",-1,"actual","2026-05-02T00:00:00Z",None,"2026-05-06T09:00:00Z","Approval was denied."),
    ("claim-plan","a5","alpha","coast.approved",1,"planned","2026-05-09T00:00:00Z",None,"2026-05-02T07:20:00Z","Approval will be granted"),
    ("claim-beta","beta1","beta","coast.approved",1,"actual","2026-05-01T00:00:00Z",None,"2026-05-01T08:00:00Z","Approval was granted"),
]
LOOKUP = """
SELECT c.id,c.polarity,s.id,s.lineage_id,s.source_sha256
FROM claim_observation AS c JOIN source_occurrence AS s ON s.id=c.source_id
WHERE c.tenant=? AND s.tenant=? AND c.proposition=?
  AND c.modality='actual' AND c.valid_from<=?
  AND (c.valid_to IS NULL OR ? < c.valid_to)
  AND c.observed_at<=? AND s.acquired_at<=?
ORDER BY s.id,c.id
"""
POLICY_SHA = hashlib.sha256(b"public-claim-support-r1:four-valued-not-objective-truth").hexdigest()


def digest(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def immutable_insert(connection: sqlite3.Connection, table: str, cols: tuple[str, ...], record: tuple) -> None:
    """Replay is idempotent only when EVERY previously inserted field agrees."""
    columns=",".join(cols)
    existing=connection.execute(f"SELECT {columns} FROM {table} WHERE id=?",(record[0],)).fetchone()
    if existing is not None:
        if tuple(existing)!=record:
            raise ValueError("REPLAY_DIFFERENT_BYTES")
        return
    slots=",".join("?" for _ in cols)
    connection.execute(f"INSERT INTO {table} ({columns}) VALUES ({slots})",record)


def load(connection: sqlite3.Connection) -> None:
    scols=("id","archive_id","native_locator","tenant","message_id","source_time",
           "acquired_at","lineage_id","original_text","source_sha256")
    ccols=("id","source_id","tenant","proposition","polarity","modality",
           "valid_from","valid_to","observed_at","excerpt")
    for record in SOURCE_ROWS:
        immutable_insert(connection,"source_occurrence",scols,(*record,digest(record[-1])))
    for record in CLAIM_ROWS:
        immutable_insert(connection,"claim_observation",ccols,record)
    connection.commit()


def query(conn: sqlite3.Connection, tenant: str, valid_at: str, known_at: str,
          proposition: str="coast.approved") -> dict:
    rows=conn.execute(LOOKUP,(tenant,tenant,proposition,valid_at,valid_at,known_at,known_at)).fetchall()
    positive={r[3] for r in rows if r[1]==1}
    negative={r[3] for r in rows if r[1]==-1}
    status=("BOTH" if positive and negative else "SUPPORTED" if positive
            else "REFUTED" if negative else "NEITHER")
    return {"status":status,
            "source_ids":sorted({r[2] for r in rows}),
            "lineages_supporting":len(positive),
            "lineages_refuting":len(negative),
            "source_hashes":sorted({r[4] for r in rows})}


def qualify() -> dict:
    cases=[
        ("before_any","alpha","2026-05-01T12:00:00Z","2026-05-11T00:00:00Z","NEITHER",0),
        ("early_known","alpha","2026-05-03T12:00:00Z","2026-05-04T00:00:00Z","REFUTED",1),
        ("late_retro","alpha","2026-05-03T12:00:00Z","2026-05-11T00:00:00Z","BOTH",3),
        ("pre_arrival","alpha","2026-05-04T12:00:00Z","2026-05-04T12:00:00Z","REFUTED",1),
        ("later_known","alpha","2026-05-04T12:00:00Z","2026-05-06T00:00:00Z","BOTH",2),
        ("late_reacquisition","alpha","2026-05-04T12:00:00Z","2026-05-07T00:00:00Z","BOTH",3),
        ("beta_private","beta","2026-05-03T12:00:00Z","2026-05-11T00:00:00Z","SUPPORTED",1),
        ("alpha_unknown","alpha","2026-05-01T12:00:00Z","2026-05-02T08:00:00Z","NEITHER",0),
    ]
    with tempfile.TemporaryDirectory(prefix="public-sqlite-bitemporal-") as directory:
        target=Path(directory)/"fixture.db"
        conn=sqlite3.connect(target)
        try:
            conn.executescript(SQL)
            load(conn)
            load(conn)
            if conn.execute("SELECT count(*) FROM source_occurrence").fetchone()[0]!=6:
                raise AssertionError("OCCURRENCE_LOST_OR_DUPLICATED")
            if conn.execute("SELECT count(*) FROM claim_observation").fetchone()[0]!=6:
                raise AssertionError("CLAIM_LOST_OR_DUPLICATED")
            if conn.execute("SELECT count(DISTINCT message_id) FROM source_occurrence WHERE tenant='alpha'").fetchone()[0]!=2:
                raise AssertionError("DUPLICATE_MESSAGE_ID_COLLAPSED")
            outcomes={}
            for name,tenant,valid_at,known_at,expect,count in cases:
                result=query(conn,tenant,valid_at,known_at)
                if (result["status"],len(result["source_ids"]))!=(expect,count):
                    raise AssertionError("TEMPORAL_CASE_"+name)
                outcomes[name]=result
            if (outcomes["late_reacquisition"]["lineages_refuting"]!=1 or
                len(outcomes["late_reacquisition"]["source_ids"])!=3):
                raise AssertionError("DUPLICATE_REACQUISITION_AS_NEW_AUTHORITY")
            if ("a5" in outcomes["late_reacquisition"]["source_ids"] or
                "beta1" in outcomes["later_known"]["source_ids"]):
                raise AssertionError("PLANNED_EVENT_OR_CROSS_TENANT_LEAK")
            for stmt in (
                "DELETE FROM source_occurrence WHERE id='a1'",
                "UPDATE source_occurrence SET original_text='altered' WHERE id='a1'",
                "DELETE FROM claim_observation WHERE id='claim-denied'",
                "UPDATE assessment_history SET verdict='SUPPORTED' WHERE id='anything'",
            ):
                try:
                    conn.execute(stmt)
                except sqlite3.IntegrityError:
                    pass
                else:
                    # A no-match UPDATE is legal SQL, so use an existing assessment below.
                    if "assessment_history" not in stmt:
                        raise AssertionError("IMMUTABILITY_GATE")
            try:
                altered=(*SOURCE_ROWS[0][:-1],"wrong earlier source",digest("wrong earlier source"))
                immutable_insert(conn,"source_occurrence",(
                    "id","archive_id","native_locator","tenant","message_id","source_time",
                    "acquired_at","lineage_id","original_text","source_sha256"),altered)
            except ValueError:
                pass
            else:
                raise AssertionError("REPLAY_MUTATED_SOURCE_ACCEPTED")
            try:
                immutable_insert(conn,"claim_observation",(
                    "id","source_id","tenant","proposition","polarity","modality",
                    "valid_from","valid_to","observed_at","excerpt"),
                    ("forged","beta1","alpha","coast.approved",1,"actual",
                     "2026-05-01T00:00:00Z",None,"2026-05-01T08:00:00Z","forgery"))
            except sqlite3.IntegrityError:
                pass
            else:
                raise AssertionError("CROSS_TENANT_CLAIM_ACCEPTED")
            for name in ("early_known","late_retro"):
                name_case=next(c for c in cases if c[0]==name)
                r=outcomes[name]
                conn.execute(
                    "INSERT INTO assessment_history VALUES (?,?,?,?,?,?,?,?)",
                    (name,"alpha","coast.approved",name_case[2],name_case[3],
                     r["status"],json.dumps(r["source_ids"],sort_keys=True),POLICY_SHA))
            conn.commit()
            conn.close()
            conn=sqlite3.connect(target)
            after=query(conn,"alpha","2026-05-03T12:00:00Z","2026-05-11T00:00:00Z")
            if after!=outcomes["late_retro"]:
                raise AssertionError("RESTART_RESULT_DRIFT")
            rows=conn.execute(
                "SELECT verdict FROM assessment_history ORDER BY known_at").fetchall()
            if rows!=[("REFUTED",),("BOTH",)]:
                raise AssertionError("HISTORICAL_ASSESSMENT_REWRITTEN")
            try:
                conn.execute("UPDATE assessment_history SET verdict='SUPPORTED' WHERE id='early_known'")
            except sqlite3.IntegrityError:
                pass
            else:
                raise AssertionError("ASSESSMENT_HISTORY_MUTABLE")
            plan=conn.execute(
                "EXPLAIN QUERY PLAN "+LOOKUP,
                ("alpha","alpha","coast.approved","2026-05-03T12:00:00Z",
                 "2026-05-03T12:00:00Z","2026-05-11T00:00:00Z",
                 "2026-05-11T00:00:00Z")).fetchall()
            if not any("claim_lookup" in str(row) for row in plan):
                raise AssertionError("INDEX_NOT_USED")
            return {"schema":SCHEMA,"classification":"SQLITE_NATIVE_BITEMPORAL_PROJECTION_ONLY",
                    "sqlite_version":sqlite3.sqlite_version,
                    "qualified_cases":len(cases),"source_occurrences":6,
                    "claim_observations":6,"unique_source_lineages":5,
                    "assessment_history_rows":2,"four_valued_verdicts":sorted(
                        {r["status"] for r in outcomes.values()}),
                    "retrospective_query_verified":True,
                    "conflict_preserved":True,"historical_replay_verified":True,
                    "reacquisition_not_independent_vote":True,
                    "immutable_source_guard":True,"index_used":True,
                    "model_inference":False,"native_pst_qualified":False,
                    "source_fixture_sha256":digest(json.dumps(
                        SOURCE_ROWS,ensure_ascii=False,sort_keys=True)),
                    "policy_sha256":POLICY_SHA}
        finally:
            conn.close()


if __name__ == "__main__":
    print(json.dumps(qualify(),sort_keys=True,separators=(",",":")))
