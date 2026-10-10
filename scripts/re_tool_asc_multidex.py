#!/usr/bin/env python3
"""Public-only multiclass DEX enumeration A/B control (no APK from users).

Two independent implementations enumerate the SAME archived synthetic DEX:
the source-pinned Droid ASC CLI and a small header/table reference oracle.
"""
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


def digest(data):
    return hashlib.sha256(data).hexdigest()


def header_names(data):
    """Independent DEX header/ID-table name oracle (not candidate code)."""
    get32 = lambda n: struct.unpack_from("<I", data, n)[0]
    assert data[:4] == b"dex\n"
    strings_off, types_off = get32(0x3c), get32(0x44)
    classes_off, class_count = get32(0x64), get32(0x60)
    names = []
    for k in range(class_count):
        type_idx = get32(classes_off + 32 * k)
        name_idx = get32(types_off + 4 * type_idx)
        offset = get32(strings_off + 4 * name_idx)
        # Independent small ULEB128 scanner
        while data[offset] & 0x80:
            offset += 1
        offset += 1
        end = data.index(b"\0", offset)
        names.append(data[offset:end].decode("utf-8", "strict"))
    return names


def baseline(apk, prefix):
    rows = []
    with zipfile.ZipFile(apk) as z:
        dexes = sorted(
            [p for p in z.namelist() if p == "classes.dex" or
             (p.startswith("classes") and p.endswith(".dex") and p[7:-4].isdigit())],
            key=lambda x: 1 if x == "classes.dex" else int(x[7:-4]),
        )
        for name in dexes:
            rows += header_names(z.read(name))
    return [r for r in rows if r.startswith(prefix)] if prefix else rows


def execute(command, timeout=70):
    start = time.perf_counter_ns()
    completed = subprocess.run(
        command, text=True, capture_output=True, timeout=timeout, check=False)
    return completed, (time.perf_counter_ns() - start) / 1e6


def qualify(root, out):
    from test_listclass import make_class_only_dex

    result = {
        "schema": "requal-asc-multidex/v1",
        "pin": PIN, "input_scope": "public_generated_only",
        "cases": [], "samples": 9,
        "status": "INCOMPLETE"
    }
    head, _ = execute(["git", "-C", str(root), "rev-parse", "HEAD"])
    if head.stdout.strip() != PIN or head.returncode:
        raise RuntimeError("wrong pinned upstream source checkout")

    a = ["Lcom/qualification/A%05d;" % k for k in range(2048)]
    b = ["Lorg/qualification/B%05d;" % k for k in range(2048)] + a[:128]
    dex_a, dex_b = make_class_only_dex(a), make_class_only_dex(b)
    assert header_names(dex_a) == a and header_names(dex_b) == b
    result["fixtures"] = {
        "first_sha256": digest(dex_a), "second_sha256": digest(dex_b),
        "total_definitions": len(a) + len(b), "duplicate_definitions": 128,
    }
    with tempfile.TemporaryDirectory() as directory:
        directory = Path(directory)
        for kind in (zipfile.ZIP_STORED, zipfile.ZIP_DEFLATED):
            apk = directory / ("fixture-%d.apk" % kind)
            with zipfile.ZipFile(apk, "w", compression=kind) as z:
                z.writestr("classes.dex", dex_a)
                z.writestr("classes2.dex", dex_b)
            for label, prefix in (("all", ""), ("prefix", "Lcom/qualification/"),
                                  ("missing", "Lcom/no-such-class/")):
                expected = baseline(apk, prefix)
                args = ["--prefix", prefix] if prefix else []
                cmd = [sys.executable, "-S", str(root / "main.py"), "listclass",
                       str(apk), "--threads", "2", *args]
                # Prefix in source is dotted package notation, not a descriptor;
                # the user-facing contract expects normal Java package prefixes.
                if prefix:
                    cmd[-1] = prefix[1:].rstrip("/").replace("/", ".")
                control = [sys.executable, "-S", __file__,
                           "--baseline", str(apk), "--prefix", prefix]
                diffs, source_ms, control_ms = [], [], []
                for trial in range(9):
                    # Paired fresh interpreters, alternating execution order.
                    commands = [("asc", cmd), ("oracle", control)]
                    if trial % 2:
                        commands.reverse()
                    outputs = {}
                    for name, argv in commands:
                        p, elapsed = execute(argv)
                        outputs[name] = p.stdout.splitlines()
                        (source_ms if name == "asc" else control_ms).append(elapsed)
                        if p.returncode:
                            raise RuntimeError("%s %s rc=%d stderr=%s" %
                                               (name, label, p.returncode, p.stderr[-500:]))
                    diffs.append(outputs["asc"] == expected == outputs["oracle"])
                result["cases"].append({
                    "id": "%s-%s" % (kind, label),
                    "pass": all(diffs),
                    "expected_definitions": len(expected),
                    "pair_count": 9,
                    "source_median_ms": round(statistics.median(source_ms), 4),
                    "oracle_median_ms": round(statistics.median(control_ms), 4),
                    "note": "same fixture, same subprocess startup, read-only enumeration only",
                })
        damaged = bytearray(dex_a)
        class_offset = struct.unpack_from("<I", damaged, 0x64)[0]
        struct.pack_into("<I", damaged, class_offset, 0xffffffff)
        corrupt_apk = directory / "corrupt.apk"
        with zipfile.ZipFile(corrupt_apk, "w") as z:
            z.writestr("classes.dex", damaged)
        p, _ = execute([sys.executable, "-S", str(root / "main.py"),
                        "listclass", str(corrupt_apk)])
        result["cases"].append({
            "id": "malformed-type-index-rejected",
            "pass": p.returncode != 0 and "bad class_def->type_idx" in p.stderr,
            "exit_code": p.returncode,
        })
    result["status"] = "PASS_SCOPED_MULTIDEX" if all(x["pass"] for x in result["cases"]) else "FAIL"
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n")
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0 if result["status"].startswith("PASS") else 1


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--baseline", type=Path)
    parser.add_argument("--prefix", default="")
    parser.add_argument("--source", type=Path)
    parser.add_argument("--out", type=Path)
    args = parser.parse_args()
    if args.baseline:
        rows = baseline(args.baseline, args.prefix)
        if rows:
            sys.stdout.write("\n".join(rows) + "\n")
    else:
        if not args.source or not args.out:
            parser.error("--source and --out required")
        sys.path[0:0] = [str(args.source), str(args.source / "tests")]
        try:
            sys.exit(qualify(args.source, args.out))
        except Exception as exc:
            args.out.parent.mkdir(parents=True, exist_ok=True)
            args.out.write_text(json.dumps({
                "status": "FAIL_OR_INCOMPLETE",
                "error": type(exc).__name__ + ": " + str(exc),
                "pin": PIN,
            }, indent=2) + "\n")
            raise
