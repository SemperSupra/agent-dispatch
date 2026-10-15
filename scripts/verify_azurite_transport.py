#!/usr/bin/env python3
"""Independent synthetic Azurite Blob ETag/replay oracle; no cloud access."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import sys

IMAGE = "mcr.microsoft.com/azure-storage/azurite@sha256:830430c1da1a2d537e08f3e6764dd1f5ae00cf0346bcaf625b968ec3f0971fd5"
REVISION = "3.37.0"
SCHEMA = "azurite-transport-phase/v1"


class Denied(ValueError):
    pass


def _unique_pairs(pairs):
    out = {}
    for k, v in pairs:
        if k in out:
            raise Denied("DUPLICATE_FIELD")
        out[k] = v
    return out


def _parse(raw):
    if not isinstance(raw, bytes) or not 50 <= len(raw) <= 2048:
        raise Denied("PHASE_BYTES_DENIED")
    try:
        obj = json.loads(raw.decode("utf-8"), object_pairs_hook=_unique_pairs,
                         parse_constant=lambda _: (_ for _ in ()).throw(Denied("INVALID_NUMBER")))
    except (ValueError, UnicodeDecodeError, json.JSONDecodeError) as err:
        raise Denied("PHASE_JSON_DENIED") from err
    if not isinstance(obj, dict):
        raise Denied("PHASE_SHAPE_DENIED")
    return obj


def verify(write_raw, recovery_raw, trusted_sha, trusted_run):
    if not isinstance(trusted_sha, str) or not re.fullmatch(r"[0-9a-f]{40}", trusted_sha):
        raise Denied("SOURCE_INVALID")
    if not isinstance(trusted_run, str) or not re.fullmatch(r"[1-9][0-9]{0,19}", trusted_run):
        raise Denied("RUN_ID_INVALID")
    a, b = _parse(write_raw), _parse(recovery_raw)
    if set(a) != {"schema", "phase", "etag", "sha256", "length",
                  "create_status", "replay_status", "provider_access_verified"}:
        raise Denied("WRITE_FIELDS_DENIED")
    if set(b) != {"schema", "phase", "old_etag", "etag", "sha256", "length",
                  "stale_write_status", "conditional_update_status", "stale_read_status",
                  "recovered_from_new_process", "provider_access_verified"}:
        raise Denied("RECOVERY_FIELDS_DENIED")
    if a["schema"] != SCHEMA or b["schema"] != SCHEMA or a["phase"] != "write" or b["phase"] != "recover":
        raise Denied("PHASE_SCHEMA_DENIED")
    if (a["provider_access_verified"] is not False or
            b["provider_access_verified"] is not False):
        raise Denied("PROVIDER_CLAIM_DENIED")
    expected = {
        "write": b"public-synthetic-artifact-v1\n",
        "recover": b"public-synthetic-artifact-v2\n",
    }
    if (type(a["length"]) is not int or a["length"] != len(expected["write"]) or
            type(b["length"]) is not int or b["length"] != len(expected["recover"])):
        raise Denied("PAYLOAD_LENGTH_DENIED")
    if (a["sha256"] != hashlib.sha256(expected["write"]).hexdigest() or
            b["sha256"] != hashlib.sha256(expected["recover"]).hexdigest()):
        raise Denied("PAYLOAD_DIGEST_DENIED")
    if (type(a["create_status"]) is not int or a["create_status"] != 201 or
            type(a["replay_status"]) is not int or a["replay_status"] != 412 or
            type(b["stale_write_status"]) is not int or b["stale_write_status"] != 412 or
            type(b["stale_read_status"]) is not int or b["stale_read_status"] != 412 or
            type(b["conditional_update_status"]) is not int or
            b["conditional_update_status"] != 201):
        raise Denied("CONDITIONAL_STORAGE_SEMANTICS_DENIED")
    if (not isinstance(a["etag"], str) or not re.fullmatch(r'"[^"]{1,128}"', a["etag"]) or
            not isinstance(b["etag"], str) or not re.fullmatch(r'"[^"]{1,128}"', b["etag"]) or
            b["old_etag"] != a["etag"] or b["etag"] == a["etag"]):
        raise Denied("REVISION_BINDING_DENIED")
    if b["recovered_from_new_process"] is not True:
        raise Denied("RECOVERY_NOT_PROVEN")
    return {
        "schema": "azurite-transport-independent-verdict/v1",
        "classification": "EMULATOR_ONLY_PASS",
        "source_sha": trusted_sha,
        "native_run_id": trusted_run,
        "runner": "ubuntu-24.04",
        "tool": "Azurite",
        "version": REVISION,
        "immutable_image": IMAGE,
        "phase_write_sha256": hashlib.sha256(write_raw).hexdigest(),
        "phase_recover_sha256": hashlib.sha256(recovery_raw).hexdigest(),
        "revision_changed": True,
        "write_replay_blocked": True,
        "stale_write_blocked": True,
        "stale_read_blocked": True,
        "fresh_client_recovered": True,
        "provider_access_verified": False,
        "data_class": "public-synthetic",
        "max_cost_usd": 0,
    }


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--write", required=True)
    ap.add_argument("--recover", required=True)
    ap.add_argument("--out", required=True)
    opts = ap.parse_args()
    try:
        receipt = verify(Path(opts.write).read_bytes(), Path(opts.recover).read_bytes(),
                         os.environ.get("GITHUB_SHA"), os.environ.get("GITHUB_RUN_ID"))
        if os.environ.get("RUNNER_ARCH") != "X64":
            raise Denied("RUNNER_SHAPE_DENIED")
        dest = Path(opts.out)
        if dest.is_symlink() or dest.exists():
            raise Denied("OUTPUT_EXISTS")
        with dest.open("x", encoding="utf-8") as fh:
            fh.write(json.dumps(receipt, sort_keys=True, indent=2) + "\n")
        print("AZURITE_TRANSPORT_INDEPENDENT_PASS")
    except (Denied, OSError):
        print("AZURITE_TRANSPORT_INDEPENDENT_BLOCKED", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
