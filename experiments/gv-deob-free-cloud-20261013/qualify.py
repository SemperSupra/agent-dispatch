#!/usr/bin/env python3
"""Public-only bounded Android deob tool work-sample. No target APK or credentials."""
import hashlib
import importlib.metadata
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import time
import traceback

ROOT = Path(os.environ.get("RUNNER_TEMP", "/tmp")) / "gv-deob-qual"
ROOT.mkdir(parents=True, exist_ok=True)
RECEIPT = ROOT / "receipt.json"
PBTK_SHA = "7ea37a44c0a277c5ffcd5308b2ab4cf1575d45ca"
JADX_SHA = "545ea2be9c242511bc145755cf4bda2485ade42966e096f8b4d3da2a230e8974"
status = {"schema": "public-synthetic-android-deob-qual/v1", "fixture": "AUTHORED_NO_PRIVATE_APK",
          "pbtk_source": PBTK_SHA, "jadx_distribution_sha256": JADX_SHA,
          "runs": {}, "overall": "UNKNOWN"}

def exec_(args, timeout=120, cwd=None):
    start = time.monotonic()
    p = subprocess.run([str(x) for x in args], capture_output=True, text=True,
                       cwd=cwd, timeout=timeout, check=False)
    return p, round(time.monotonic() - start, 3)

def record(name, state, **details):
    status["runs"][name] = {"state": state, **details}
    RECEIPT.write_text(json.dumps(status, indent=2, sort_keys=True) + "\n")

def pbtk():
    from google.protobuf.descriptor_pb2 import FileDescriptorProto
    from pbtk.extractors.from_binary import walk_binary
    proto = FileDescriptorProto()
    proto.name = "gv_qual_sample.proto"
    proto.package = "authored"
    proto.syntax = "proto2"
    message = proto.message_type.add()
    message.name = "Sample"
    for name, number, type_ in (("title", 1, 9), ("count", 2, 5)):
        f = message.field.add()
        f.name, f.number, f.type, f.label = name, number, type_, 1
    payload = proto.SerializeToString()
    source = ROOT / "synthetic_descriptor.c"
    so = ROOT / "synthetic_descriptor.so"
    array = ",".join(str(b) for b in payload)
    source.write_text("const unsigned char proto[] = {" + array + "};\n"
                      "int authored_fixture(void){ return proto[0]; }\n")
    p, build_s = exec_(["cc", "-O0", "-fPIC", "-shared", str(source), "-o", str(so)])
    if p.returncode:
        raise RuntimeError("fixture_cc_failed")
    data = so.read_bytes()
    found = list(walk_binary(data))
    if not any(name == proto.name and "message Sample" in definition and
               "string title = 1;" in definition and "int32 count = 2;" in definition
               for name, definition in found):
        raise RuntimeError("pbtk_descriptor_oracle_mismatch")
    # Adversarial structural negative: marker is gone; no phantom match.
    mutated = data.replace(b".proto", b".pr0to")
    if list(walk_binary(mutated)):
        raise RuntimeError("pbtk_false_positive_negative")
    record("pbtk_from_binary", "PASS", fixture_compiled=True,
           recovered_file_count=len(found), fields_verified=2,
           false_positive_negative="PASS", input_sha256=hashlib.sha256(data).hexdigest(),
           compile_wall_seconds=build_s)

def jadx():
    root = Path(os.environ.get("JADX_DIR", str(ROOT / "jadx")))
    jadx_path = root / "bin" / "jadx"
    if not jadx_path.is_file():
        record("jadx", "BLOCKED_TOOL_ABSENT")
        return
    sdk = Path(os.environ.get("ANDROID_HOME", "/usr/local/lib/android/sdk"))
    build_tools = sdk / "build-tools"
    candidates = sorted(build_tools.glob("*/d8"), reverse=True)
    if not candidates:
        record("jadx", "BLOCKED_D8_ABSENT")
        return
    src = ROOT / "QualProbe.java"
    cls = ROOT / "compiled"
    dex_dir = ROOT / "dex"
    out = ROOT / "jadx_out"
    cls.mkdir(exist_ok=True)
    dex_dir.mkdir(exist_ok=True)
    src.write_text("public class QualProbe {\n"
                   " public static int addSeven(int x) { return x + 7; }\n"
                   " public static String msg() { return \"authored-oracle\"; }\n}\n")
    p, javac_s = exec_(["javac", "-g:none", "-d", str(cls), str(src)])
    if p.returncode:
        raise RuntimeError("javac_fixture_failed")
    p, d8_s = exec_([str(candidates[0]), "--min-api", "21", "--output",
                      str(dex_dir), str(cls / "QualProbe.class")])
    if p.returncode:
        raise RuntimeError("d8_fixture_failed")
    dex_path = dex_dir / "classes.dex"
    if not dex_path.exists():
        raise RuntimeError("d8_missing_dex")
    p, version_s = exec_([str(jadx_path), "--version"], timeout=25)
    if p.returncode or "1.5.6" not in (p.stdout + p.stderr):
        raise RuntimeError("jadx_wrong_version")
    p, elapsed = exec_([str(jadx_path), "-d", str(out), str(dex_path)], timeout=100)
    files = list(out.rglob("*.java"))
    text = "\n".join(file.read_text(errors="replace") for file in files)
    method_recovered = "addSeven(" in text
    string_recovered = "authored-oracle" in text
    if p.returncode or not method_recovered or not string_recovered:
        record("jadx", "FAIL", exit_code=p.returncode,
               recovered_method=method_recovered, recovered_literal=string_recovered)
        return
    record("jadx", "PASS", version="1.5.6", d8_path=str(candidates[0]).split("/")[-2],
           class_count=len(files), recovered_method=True, recovered_literal=True,
           dex_sha256=hashlib.sha256(dex_path.read_bytes()).hexdigest(),
           wall_seconds=elapsed, javac_wall_seconds=javac_s, d8_wall_seconds=d8_s)

def rosal():
    try:
        ver = importlib.metadata.version("rosal")
    except importlib.metadata.PackageNotFoundError:
        record("rosal", "BLOCKED_INSTALL")
        return
    p, elapsed = exec_([str(ROOT / "venv" / "bin" / "rosal"), "--help"], timeout=35)
    if p.returncode:
        record("rosal", "BLOCKED_RUNTIME", version=ver, exit_code=p.returncode)
    else:
        record("rosal", "PASS_CLI_PREFLIGHT_ONLY", version=ver,
           wall_seconds=elapsed, matching_semantics="NOT_RUN_NO_ANDROIDX_FIXTURE")
    # Isolated source-only challenge: public AndroidX AAR -> D8 -> descriptor rename.
    # This is NOT a sample of Google Voice or an APK downloaded from a private source.
    try:
        import io
        import re
        import struct
        import zlib
        import zipfile
        sdk = Path(os.environ.get("ANDROID_HOME", "/usr/local/lib/android/sdk"))
        candidates = sorted((sdk / "build-tools").glob("*/d8"), reverse=True)
        if not candidates:
            record("rosal", "BLOCKED_D8_FOR_MATCHER", version=ver)
            return
        sdkroot = Path.home() / "Android"
        sdkroot.mkdir(exist_ok=True)
        link = sdkroot / "Sdk"
        if not link.exists():
            link.symlink_to(sdk, target_is_directory=True)
        aar = ROOT / "androidx-activity-1.8.1.aar"
        url = "https://dl.google.com/dl/android/maven2/androidx/activity/activity/1.8.1/activity-1.8.1.aar"
        p, _ = exec_(["curl", "--retry", "1", "--max-time", "65", "-fsSL",
                       "-o", str(aar), url], timeout=78)
        if p.returncode or not aar.exists():
            record("rosal", "BLOCKED_PUBLIC_AAR_FETCH", version=ver)
            return
        with zipfile.ZipFile(aar) as archive:
            jar = archive.read("classes.jar")
        libjar = ROOT / "activity-classes.jar"
        libjar.write_bytes(jar)
        dexdir = ROOT / "rosal_dex"
        dexdir.mkdir(exist_ok=True)
        p, build_wall = exec_([str(candidates[0]), "--min-api", "21",
                               "--output", str(dexdir), str(libjar)], timeout=85)
        dexfile = dexdir / "classes.dex"
        if p.returncode or not dexfile.exists():
            record("rosal", "BLOCKED_SYNTHETIC_D8", version=ver, exit_code=p.returncode)
            return
        data = bytearray(dexfile.read_bytes())
        matches = list(re.finditer(rb"Landroidx/activity/[A-Za-z0-9_$\/]{5,60};", data))
        if not matches:
            record("rosal", "BLOCKED_NO_DESCRIPTOR_FIXTURE", version=ver)
            return
        chosen = next((m for m in matches if b"Api34Impl;" in m.group()), matches[0])
        original = chosen.group()
        prefix, sep, name = original.rpartition(b"/")
        alternate = prefix + sep + b"z" * len(name[:-1]) + b";"
        if alternate == original or len(alternate) != len(original) or alternate in data:
            raise ValueError("known_name_mutation_invalid")
        data[chosen.start():chosen.end()] = alternate
        data[12:32] = hashlib.sha1(data[32:]).digest()
        data[8:12] = struct.pack("<I", zlib.adler32(data[12:]) & 0xffffffff)
        sample = ROOT / "authored-androidx-rename.apk"
        with zipfile.ZipFile(sample, "w", zipfile.ZIP_DEFLATED) as out:
            out.writestr("AndroidManifest.xml",
                         '<?xml version="1.0" encoding="utf-8"?>'
                         '<manifest xmlns:android="http://schemas.android.com/apk/res/android" '
                         'package="org.example.authored"><application/></manifest>')
            out.writestr("classes.dex", data)
            out.writestr("META-INF/androidx.activity_activity.version", "1.8.1")
        work = ROOT / "rosal_work"
        p, seconds = exec_([str(ROOT / "venv" / "bin" / "rosal"),
                            "--apk", str(sample), "--work-dir", str(work)], timeout=155)
        results = work / "matches.json"
        if p.returncode or not results.exists():
            record("rosal", "BLOCKED_MATCHER_EXECUTION", version=ver,
                   exit_code=p.returncode, has_result=results.exists(),
                   wall_seconds=seconds)
            return
        result = json.loads(results.read_text(encoding="utf-8"))
        items = result.get("matches", []) if isinstance(result, dict) else []
        hits = [x for x in items if x.get("library_class") == original.decode()
                and x.get("target_class") == alternate.decode()]
        record("rosal", "PASS_KNOWN_ALIAS" if hits else "NO_CORRECT_ALIAS",
               version=ver, inferred_match_count=len(items),
               correct_alias_count=len(hits), wall_seconds=seconds,
               aar_sha256=hashlib.sha256(aar.read_bytes()).hexdigest(),
               synthetic_apk_sha256=hashlib.sha256(sample.read_bytes()).hexdigest(),
               original_descriptor=original.decode(),
               synthetic_alias=alternate.decode(), source="public_androidx_1.8.1")
    except subprocess.TimeoutExpired:
        record("rosal", "BLOCKED_MATCHER_TIMEOUT", version=ver)
    except Exception as exc:
        record("rosal", "BLOCKED_OR_FAIL_MATCHER", version=ver,
               error_type=type(exc).__name__, reason=str(exc)[:100])

try:
    # Admission: public-only code and fixture, no GitHub write credential.
    sys.path.insert(0, str(ROOT / "pbtk" / "src"))
    pbtk()
except Exception as exc:
    record("pbtk_from_binary", "FAIL", error_type=type(exc).__name__,
           reason=str(exc)[:160])
try:
    jadx()
except Exception as exc:
    record("jadx", "FAIL", error_type=type(exc).__name__,
           reason=str(exc)[:160])
try:
    rosal()
except Exception as exc:
    record("rosal", "FAIL", error_type=type(exc).__name__,
           reason=str(exc)[:160])
required = (status["runs"]["pbtk_from_binary"]["state"] == "PASS" and
            status["runs"]["jadx"]["state"] == "PASS")
status["overall"] = "PASS_BOUNDED_SYNTHETIC" if required else "BLOCKED_OR_FAIL"
RECEIPT.write_text(json.dumps(status, indent=2, sort_keys=True) + "\n")
print(json.dumps(status, sort_keys=True))
sys.exit(0 if required else 1)
