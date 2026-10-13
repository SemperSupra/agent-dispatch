#!/usr/bin/env python3
"""Public-only multilingual APK tool interview, with authored fixtures and held-out oracles.

No access to Google Voice, accounts, or private source. Candidate failures are reported
as FAIL/BLOCKED/UNQUALIFIED, never promoted as acceptance.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import time
import zipfile

ROOT = Path(os.environ.get("RUNNER_TEMP", "/tmp")) / "gv-apk-multilingual"
ROOT.mkdir(parents=True, exist_ok=True)
PINS = {"reproto": "906efc5f44ffa9bffa31e056a9de55c7107bdab8",
        "protorev_version": "v0.1.0",
        "protorev_sha256": "462053ee7a8db7c70486e0324cd671a9f356a860cafe61b62e589a617dd32600"}
state = {"schema": "gv-apk-multilingual-qualification/v1",
         "venue": "PUBLIC_SYNTHETIC_NO_REAL_GOOGLE_VOICE", "pins": PINS, "results": {}}

def run(args, timeout=75):
    t = time.monotonic()
    p = subprocess.run([str(x) for x in args], text=True, capture_output=True,
                       check=False, timeout=timeout)
    return p, round(time.monotonic() - t, 3)

def report(tool, status, **details):
    state["results"][tool] = {"status": status, **details}
    (ROOT / "receipt.json").write_text(json.dumps(state, sort_keys=True, indent=2) + "\n")

def protorev():
    executable = ROOT / "protorev"
    if not executable.is_file():
        report("protorev", "BLOCKED_BINARY_MISSING")
        return
    samples = ROOT / "raw"
    samples.mkdir(exist_ok=True)
    # Exact known-answer raw protobuf messages; no framing, no semantic inference.
    before = bytes.fromhex("08 96 01 12 05 68 65 6c 6c 6f")
    after = bytes.fromhex("08 97 01 12 05 77 6f 72 6c 64")
    (samples / "a.pb").write_bytes(before)
    (samples / "b.pb").write_bytes(after)
    cmd, seconds = run([executable, "dump", samples / "a.pb"])
    if cmd.returncode != 0 or "field 1" not in cmd.stdout or "field 2" not in cmd.stdout:
        report("protorev", "FAIL_RAW_WIRE_ORACLE", exit_code=cmd.returncode)
        return
    schema, _ = run([executable, "schema", samples / "a.pb", samples / "b.pb"])
    if schema.returncode != 0 or "field_1" not in schema.stdout or "field_2" not in schema.stdout:
        report("protorev", "FAIL_SCHEMA_FIELDS", exit_code=schema.returncode)
        return
    bad = samples / "invalid.pb"
    bad.write_bytes(bytes.fromhex("80"))
    negative, _ = run([executable, "dump", bad])
    if negative.returncode == 0:
        report("protorev", "FAIL_ACCEPTED_TRUNCATED_VARINT")
        return
    report("protorev", "PASS_WIRE_FIELDS_AND_NEGATIVE",
           recovered_field_numbers=[1, 2],
           raw_sample_sha256=hashlib.sha256(before).hexdigest(),
           schema_semantic_field_names="UNKNOWN",
           malformed_varint_rejected=True,
           wall_seconds=seconds)

def reproto():
    source = ROOT / "reproto"
    if not (source / "main.py").is_file():
        report("reproto", "BLOCKED_SOURCE_MISSING")
        return
    help_run, _ = run([sys.executable, source / "main.py", "--help"], timeout=35)
    if help_run.returncode:
        report("reproto", "FAIL_CLI_PREFLIGHT", exit_code=help_run.returncode)
        return
    base = ROOT / "reproto_java"
    path = base / "com" / "example" / "SampleMessage.java"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("""package com.example;
public final class SampleMessage extends GeneratedMessageLite {
  public static final int TITLE_FIELD_NUMBER = 1;
  public static final int COUNT_FIELD_NUMBER = 2;
  private String title_ = "";
  private int count_;
  protected Object dynamicMethod(Object type, Object unused1, Object unused2) {
    return GeneratedMessageLite.newMessageInfo(DEFAULT_INSTANCE, "\\\\u0000\\\\u0002\\\\u0000\\\\u0000\\\\u0001\\\\u0002\\\\u0002\\\\u0000\\\\u0000\\\\u0000\\\\u0001\\\\u0208\\\\u0002\\\\u0004", new Object[]{"title_", "count_"});
  }
}
""")
    output = ROOT / "reproto_output"
    output.mkdir(exist_ok=True)
    trial, elapsed = run([sys.executable, source / "main.py", base,
                          "com.example.SampleMessage", output, "--log-dir",
                          ROOT / "reproto_logs"], timeout=75)
    generated = list(output.rglob("*.proto"))
    if trial.returncode != 0:
        report("reproto", "FAIL_SYNTHETIC_JAVA_INPUT", exit_code=trial.returncode,
               reason="Generated-like Java parser failed; not tested against compiler-generated Lite",
               stderr_excerpt=trial.stderr[-180:], stdout_excerpt=trial.stdout[-180:])
        return
    txt = "\n".join(p.read_text(errors="replace") for p in generated)
    if not generated or (" = 1;" not in txt and " = 2;" not in txt):
        report("reproto", "NOT_QUALIFIED_NO_FIELD_EVIDENCE",
               generated_count=len(generated))
        return
    report("reproto", "PASS_GENERATED_LIKE_ONLY_NOT_LITE_COMPILER",
           recovered_field_number_1=" = 1;" in txt,
           recovered_field_number_2=" = 2;" in txt,
           generated_file_count=len(generated), elapsed=elapsed,
           true_generated_lite_roundtrip="NOT_RUN")

def apk():
    src = ROOT / "ApkProbe.java"
    cls = ROOT / "classes"
    dexdir = ROOT / "dex"
    cls.mkdir(exist_ok=True)
    dexdir.mkdir(exist_ok=True)
    src.write_text('public class ApkProbe { public static int seven(int x) { return x + 7; } }\n')
    p, _ = run(["javac", "-d", cls, src], timeout=40)
    if p.returncode:
        report("apk_fixture", "FAIL_JAVAC")
        return
    sdk = Path(os.environ.get("ANDROID_HOME", "/usr/local/lib/android/sdk"))
    tools = sorted((sdk / "build-tools").glob("*/d8"), reverse=True)
    if not tools:
        report("apk_fixture", "BLOCKED_D8_MISSING")
        return
    p, _ = run([tools[0], "--min-api", "21", "--output", dexdir, cls / "ApkProbe.class"], timeout=75)
    dex = dexdir / "classes.dex"
    if p.returncode or not dex.exists():
        report("apk_fixture", "FAIL_D8")
        return
    blob = dex.read_bytes()
    if not blob.startswith(b"dex\n"):
        report("apk_fixture", "FAIL_NOT_DEX")
        return
    apk = ROOT / "authored-no-manifest.apk"
    with zipfile.ZipFile(apk, "w") as z:
        z.writestr("classes.dex", blob)
    state["apk"] = {"dex_sha256": hashlib.sha256(blob).hexdigest(),
                    "zip_sha256": hashlib.sha256(apk.read_bytes()).hexdigest(),
                    "has_android_binary_manifest": False}
    report("apk_fixture", "PASS_DEX_AUTHORED")

def androguard():
    from androguard.core.dex import DEX
    data = (ROOT / "dex" / "classes.dex").read_bytes()
    d = DEX(data)
    class_names = set(d.get_classes_names())
    if "LApkProbe;" not in class_names:
        report("androguard", "FAIL_CLASS_NOT_IDENTIFIED",
               class_count=len(class_names))
        return
    try:
        DEX(b"bad dex")
    except Exception:
        negative = True
    else:
        negative = False
    report("androguard", "PASS_DEX_CLASS_AND_NEGATIVE" if negative else "FAIL_BAD_DEX_ACCEPTED",
           recovered_class=True, class_count=len(class_names),
           invalid_dex_rejected=negative,
           independently_observed_dex_sha256=hashlib.sha256(data).hexdigest())

def apkid():
    exe = ROOT / "venv" / "bin" / "apkid"
    if not exe.exists():
        report("apkid", "BLOCKED_INSTALL_OR_CLI")
        return
    sample = ROOT / "dex" / "classes.dex"
    result, wall = run([exe, "-j", sample], timeout=65)
    if result.returncode:
        report("apkid", "FAIL_SCANNER_EXIT", exit_code=result.returncode)
        return
    try:
        parsed = json.loads(result.stdout)
    except ValueError:
        report("apkid", "FAIL_NOT_JSON")
        return
    report("apkid", "PASS_SCANNER_FORMAT_ONLY",
           tool_detected_protector="NOT_ASSERTED",
           result_kind=type(parsed).__name__, elapsed=wall)

def main():
    lane = argparse.ArgumentParser()
    lane.add_argument("--lane", choices=["protocol", "apk"], required=True)
    args = lane.parse_args()
    functions = [protorev, reproto] if args.lane == "protocol" else [apk, androguard, apkid]
    for fn in functions:
        try:
            fn()
        except Exception as error:
            report(fn.__name__, "FAIL_EXCEPTION",
                   error_type=type(error).__name__, explanation=str(error)[:150])
    mandatory = ["protorev"] if args.lane == "protocol" else ["apk_fixture", "androguard"]
    states = {x: y["status"] for x, y in state["results"].items()}
    qualified = all(states.get(x, "").startswith("PASS") for x in mandatory)
    state["overall"] = "PASS_REQUIRED_WITH_CANDIDATE_LIMITS" if qualified else "FAIL_REQUIRED"
    (ROOT / "receipt.json").write_text(json.dumps(state, sort_keys=True, indent=2) + "\n")
    print(json.dumps({"lane": args.lane, "overall": state["overall"],
                      "results": states}, sort_keys=True))
    sys.exit(0 if qualified else 1)

if __name__ == "__main__":
    main()
