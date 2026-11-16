#!/usr/bin/env python3
"""R66 public-safe HMAC-witness/SQLite rollback oracle; NOT a trusted external high-water."""
import hashlib
import hmac
import json
import os
from pathlib import Path
import shutil
import sqlite3
import tempfile

def canonical(data):
    return json.dumps(data, sort_keys=True, separators=(",", ":"), allow_nan=False).encode()

def no_duplicates(pairs):
    out = {}
    for key, value in pairs:
        if key in out:
            raise ValueError("duplicate JSON key")
        out[key] = value
    return out

def issue_witness(key, data):
    if len(key) < 32:
        raise ValueError("insufficient key material")
    return {"v": 1, "data": data, "mac": hmac.new(key, canonical(data), hashlib.sha256).hexdigest()}

def read_state(db):
    try:
        con = sqlite3.connect("file:" + str(db) + "?mode=ro", uri=True, timeout=2)
        try:
            rows = dict(con.execute("SELECT name, value FROM state"))
        finally:
            con.close()
        if set(rows) != {"epoch", "budget", "effect"}:
            return None
        return rows
    except (sqlite3.Error, OSError, ValueError):
        return None

def audit(db, receipt_path, key):
    if not receipt_path.is_file():
        return "HOLD_MISSING_WITNESS"
    if len(key) < 32:
        return "HOLD_KEY_UNAVAILABLE"
    try:
        raw = receipt_path.read_bytes()
        if len(raw) > 4096:
            return "HOLD_INVALID_WITNESS"
        doc = json.loads(raw.decode("utf-8"), object_pairs_hook=no_duplicates)
        if (not isinstance(doc, dict) or set(doc) != {"v", "data", "mac"} or
            doc["v"] != 1 or not isinstance(doc["data"], dict) or
            set(doc["data"]) != {"epoch", "budget", "effect"} or
            not all(isinstance(v, str) for v in doc["data"].values()) or
            not isinstance(doc["mac"], str)):
            return "HOLD_INVALID_WITNESS"
        expected = hmac.new(key, canonical(doc["data"]), hashlib.sha256).hexdigest()
        if not hmac.compare_digest(doc["mac"], expected):
            return "HOLD_INVALID_WITNESS"
    except (OSError, ValueError, TypeError, UnicodeError):
        return "HOLD_INVALID_WITNESS"
    state = read_state(db)
    if state != doc["data"]:
        return "HOLD_INCONSISTENT_RESTORED_HIGH_WATER"
    # Signature/integrity + local state match are NOT anti-rollback.
    # This guard does not authorize external effects without a nonrollbackable anchor.
    return "MATCH_ONLY_HOLD_MONOTONIC_ANCHOR_UNPROVEN"

def init_db(db, state):
    with sqlite3.connect(db) as con:
        con.execute("CREATE TABLE state (name TEXT PRIMARY KEY, value TEXT NOT NULL)")
        con.executemany("INSERT INTO state(name, value) VALUES (?, ?)", state.items())

def set_state(db, state):
    with sqlite3.connect(db) as con:
        con.executemany("UPDATE state SET value=? WHERE name=?", [(v, k) for k, v in state.items()])

def save_receipt(path, receipt):
    path.write_bytes(canonical(receipt))

def main():
    key = os.urandom(32)  # test-only, never logged or persisted
    old = {"epoch": "7", "budget": "1", "effect": "NONE"}
    current = {"epoch": "8", "budget": "0", "effect": "UNKNOWN"}
    with tempfile.TemporaryDirectory(prefix="r66-witness-") as temp:
        root = Path(temp)
        db = root / "ledger.db"
        backup = root / "old.db"
        witness = root / "witness.json"
        init_db(db, old)
        shutil.copy2(db, backup)
        old_signed = issue_witness(key, old)
        set_state(db, current)
        save_receipt(witness, issue_witness(key, current))
        assert audit(db, witness, key) == "MATCH_ONLY_HOLD_MONOTONIC_ANCHOR_UNPROVEN"
        # A valid independently retained newer witness detects stale database restoration.
        shutil.copy2(backup, db)
        assert audit(db, witness, key) == "HOLD_INCONSISTENT_RESTORED_HIGH_WATER"
        # Changed signed payload without its MAC cannot be used to reopen budget.
        forged = issue_witness(key, current)
        forged["data"]["budget"] = "1"
        save_receipt(witness, forged)
        assert audit(db, witness, key) == "HOLD_INVALID_WITNESS"
        witness.unlink()
        assert audit(db, witness, key) == "HOLD_MISSING_WITNESS"
        save_receipt(witness, old_signed)
        # CRITICAL expected negative: privileged rollback of BOTH valid witness and DB
        # defeats integrity detection. Even a valid match MUST NOT authorize an effect.
        assert audit(db, witness, key) == "MATCH_ONLY_HOLD_MONOTONIC_ANCHOR_UNPROVEN"
        assert audit(db, witness, os.urandom(32)) == "HOLD_INVALID_WITNESS"
        print(json.dumps({
            "r66_hmac_sqlite_rollback_oracle": "PASS",
            "restored_database_against_newer_witness": "HOLD",
            "tamper": "HOLD",
            "missing_witness": "HOLD",
            "wrong_key": "HOLD",
            "rollback_both_witness_and_database": "EXPECTED_RED_TO_ANTI_ROLLBACK",
            "release_gate": "HOLD_MONOTONIC_ANCHOR_UNPROVEN",
            "real_external_witness": "NOT_TESTED",
            "actual_effect_sink": "NOT_TESTED"
        }, sort_keys=True))

if __name__ == "__main__":
    main()
