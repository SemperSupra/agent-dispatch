#!/usr/bin/env python3
"""Droid ASC multi-DEX reference workload: independent byte-layout oracle."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import statistics
import struct
import subprocess
import sys
import tempfile
import time
import zipfile

PIN = "464f9fef0db41099c4cf3f55c78b33f2606780d2"


def result(cmd):
    start = time.perf_counter_ns()
    run = subprocess.run(cmd, capture_output=True, text=True, timeout=90)
    return run, round((time.perf_counter_ns() - start) / 1e6, 5)


def expected(apk, query):
    rows = []
    with zipfile.ZipFile(apk) as archive:
        names = sorted((name for name in archive.namelist() if
                        name == "classes.dex" or
                        name.startswith("classes") and name.endswith(".dex") and
                        name[7:-4].isdigit()),
                       key=lambda name: 1 if name == "classes.dex" else int(name[7:-4]))
        for name in names:
            data = archive.read(name)
            assert data[:8] == b"dex\n035\0"
            strings_size, strings_off = struct.unpack_from("<II", data, 56)
            assert strings_size == 6
            # Independent literal string table oracle: target is ID 5.
            string_at_5 = struct.unpack_from("<I", data, strings_off + 4 * 5)[0]
            assert data[string_at_5 + 1:string_at_5 + 6] == b"token"
            class_off = struct.unpack_from("<I", data, 0x64)[0]
            class_data = struct.unpack_from("<I", data, class_off + 24)[0]
            # Authored fixture: four ULEBs (0 fields, 2 direct methods, 0 virtual)
            assert data[class_data:class_data+4] == bytes([0, 0, 2, 0])
            method_one = data[class_data+4:class_data+6]
            assert method_one == bytes([0, 9])
            # Parse first method code-offset ULEB; second method shares it.
            def varint(pos):
                value = shift = 0
                while True:
                    b = data[pos]; pos += 1
                    value |= (b & 127) << shift
                    if b < 128: return value, pos
                    shift += 7
            code, pos = varint(class_data+6)
            assert data[pos:pos+2] == bytes([1,9])
            second, _ = varint(pos+2)
            assert code == second and code > 0
            assert data[code+16:code+20] == bytes([0x1a, 0x00, 0x05, 0x00])
            if query == "token":
                rows.extend(name + " | Lexample/Test;->" + method + " | matched=(token)"
                            for method in ("first", "second"))
    return sorted(rows)


def qualify(root, out):
    sys.path[0:0] = [str(root), str(root / "tests")]
    from dex_fixture import make_dex
    git, _ = result(["git", "-C", str(root), "rev-parse", "HEAD"])
    assert git.stdout.strip() == PIN
    dex = make_dex()
    receipt = {
        "schema": "requal-asc-multidex-xref/v1",
        "upstream_commit": PIN,
        "fixture_sha256": hashlib.sha256(dex).hexdigest(),
        "dex_members": 64,
        "references_expected": 128,
        "case_results": [],
        "status": "NOT_RUN",
    }
    with tempfile.TemporaryDirectory() as td:
        for compression in (zipfile.ZIP_STORED, zipfile.ZIP_DEFLATED):
            apk = Path(td) / ("xref-%d.apk" % compression)
            with zipfile.ZipFile(apk, "w", compression=compression) as z:
                for k in range(1,65):
                    z.writestr("classes.dex" if k == 1 else "classes%d.dex" % k, dex)
            for query in ("token", "__not-present__"):
                oracle = expected(apk, query if query=="token" else None)
                got_ms = []
                paired = []
                for repeat in range(5):
                    p, ms = result([
                        sys.executable, "-S", str(root/"main.py"), "findrefs",
                        str(apk), "--threads", "4", "string", query
                    ])
                    got_ms.append(ms)
                    got = sorted(p.stdout.splitlines())
                    paired.append(p.returncode == 0 and got == oracle)
                receipt["case_results"].append({
                    "compression": compression,
                    "query_type": "hit" if query == "token" else "absent",
                    "samples": 5,
                    "expected_lines": len(oracle),
                    "passed": all(paired),
                    "median_wall_ms": statistics.median(got_ms),
                })
    receipt["status"] = "PASS_SCOPED_XREF" if all(x["passed"] for x in receipt["case_results"]) else "FAIL"
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(receipt, indent=2, sort_keys=True)+"\n")
    print(json.dumps(receipt, indent=2, sort_keys=True))
    return 0 if receipt["status"]=="PASS_SCOPED_XREF" else 1


if __name__ == "__main__":
    p=argparse.ArgumentParser()
    p.add_argument("--source", type=Path, required=True)
    p.add_argument("--out", type=Path, required=True)
    a=p.parse_args()
    try: sys.exit(qualify(a.source,a.out))
    except Exception as e:
        a.out.parent.mkdir(parents=True, exist_ok=True)
        a.out.write_text(json.dumps({"status":"FAIL_OR_INCOMPLETE","error":str(e)})+"\n")
        raise
