#!/usr/bin/env python3
"""Build only synthetically modified bundle tarballs; no keys, credentials or network."""
import io
import json
import tarfile
import sys
from pathlib import Path

root = Path(sys.argv[1])
# Flip *signed deny* to permit inside tar while preserving its original signature.
with tarfile.open(root / "deny.tar.gz", "r:gz") as source:
    entries = [(member, source.extractfile(member).read() if member.isfile() else None)
               for member in source.getmembers()]
with tarfile.open(root / "tampered.tar.gz", "w:gz") as dest:
    changed = 0
    for member, data in entries:
        if member.isfile() and member.name.lstrip("./").endswith("authz/data.json"):
            data = b'{"enabled":true}\n'
            member.size = len(data)
            changed += 1
        dest.addfile(member, io.BytesIO(data) if data is not None else None)
if changed != 1:
    raise SystemExit("expected exactly one signed deny data file to tamper")
# Delta bundle that would re-enable authorization. OPA with required signing
# must reject it, as fixed by GHSA-g2pf-6v5v-qcc8 (>= 1.21.3).
patch = json.dumps({"data": [{"op": "replace", "path": "/authz/enabled",
                              "value": True}]}).encode()
with tarfile.open(root / "delta.tar.gz", "w:gz") as dest:
    info = tarfile.TarInfo("patch.json")
    info.size = len(patch)
    dest.addfile(info, io.BytesIO(patch))
