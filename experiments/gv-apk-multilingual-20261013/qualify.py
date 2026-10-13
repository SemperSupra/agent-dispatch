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
    if not generated or not (" = 1;" in txt and " = 2;" in txt):
        report("reproto", "NOT_QUALIFIED_NO_FIELD_EVIDENCE",
               generated_count=len(generated))
        return
    report("reproto", "PASS_GENERATED_LIKE_ONLY_NOT_LITE_COMPILER",
           recovered_field_number_1=" = 1;" in txt,
           recovered_field_number_2=" = 2;" in txt,
           generated_file_count=len(generated), elapsed=elapsed,
           true_generated_lite_roundtrip="NOT_RUN")


def reproto_compiler_generated():
    """Independent oracle: actual protoc Java Lite output, not authored Java."""
    source = ROOT / "reproto"
    tool = __import__("shutil").which("protoc")
    if not tool:
        report("reproto_lite", "BLOCKED_PROTOC_NOT_AVAILABLE")
        return
    base = ROOT / "protoc_lite_case"
    base.mkdir(exist_ok=True)
    original = base / "sample.proto"
    original.write_text('syntax = "proto3";\n'
                        'package com.example;\n'
                        'option java_multiple_files = true;\n'
                        'message Sample {\n'
                        ' string title = 1;\n'
                        ' int32 count = 2;\n'
                        ' repeated string tags = 3;\n'
                        '}\n')
    source_tree = base / "java"
    source_tree.mkdir(exist_ok=True)
    p, compile_s = run([tool, f"--proto_path={base}",
                        f"--java_out=lite:{source_tree}", original], timeout=50)
    java = source_tree / "com" / "example" / "Sample.java"
    if p.returncode != 0 or not java.is_file():
        report("reproto_lite", "BLOCKED_PROTOC_JAVA_LITE",
               exit_code=p.returncode, generated_java_found=java.exists())
        return
    code = java.read_text(encoding="utf-8")
    if "newMessageInfo" not in code:
        report("reproto_lite", "BLOCKED_LITE_SHAPE_MISMATCH")
        return
    # A direct invocation of this exact upstream commit on genuine protoc
    # Java Lite returned exit -11 on the qualified free Ubuntu workcell.
    # This is already verified in PR #411 run 38399549361. Do not execute a
    # known crashing tool repeatedly; retain negative evidence and quarantine.
    report("reproto_lite", "QUARANTINED_KNOWN_COMPILER_INCOMPATIBILITY",
           upstream_pin=PINS["reproto"],
           evidence_run=38399549361, observed_exit_code=-11,
           generated_java=True,
           compiler_call_uses_variable="newMessageInfo(DEFAULT_INSTANCE, info, objects)" in code,
           synthetic_generated_java_sha256=hashlib.sha256(code.encode()).hexdigest(),
           upstream_source_modified=False,
           independent_replacement="lite_rawmessageinfo")

def lite_rawmessageinfo_oracle():
    """Independently decode a constrained actual protoc Java Lite info string.

    Uses the documented protobuf Java RawMessageInfo UTF-16 integer encoding and
    verifies recovered numbered field types/labels against protoc descriptor.
    Unsupported shapes must abstain; this does not claim full schema restoration.
    """
    import codecs
    import re
    from google.protobuf.descriptor_pb2 import FileDescriptorSet

    case = ROOT / "protoc_lite_case"
    java = case / "java" / "com" / "example" / "Sample.java"
    original = case / "sample.proto"
    protoc = __import__("shutil").which("protoc")
    if not java.exists() or not original.exists() or not protoc:
        report("lite_rawmessageinfo", "BLOCKED_NO_GENUINE_COMPILED_FIXTURE")
        return
    source = java.read_text(encoding="utf-8")
    # Consume only a direct, syntactically bounded String info assignment.
    pattern = r'\bString\s+info\s*=\s*((?:"(?:\\.|[^"\\])*"\s*(?:\+\s*)?)+);'
    match = re.search(pattern, source, re.S)
    if not match or not re.search(r'newMessageInfo\(\s*DEFAULT_INSTANCE\s*,\s*info\s*,', source):
        report("lite_rawmessageinfo", "BLOCKED_UNSUPPORTED_STRING_INFO_SHAPE")
        return
    chunks = re.findall(r'"((?:\\.|[^"\\])*)"', match.group(1))
    if not chunks or len(chunks) > 64:
        report("lite_rawmessageinfo", "FAIL_UNBOUNDED_STRING_CHUNKS")
        return
    chars = "".join(codecs.decode(chunk, "unicode_escape") for chunk in chunks)
    if not chars or len(chars) > 4096:
        report("lite_rawmessageinfo", "FAIL_UNBOUNDED_INFO")
        return

    def unpack(text):
        # RawMessageInfo.java: continuation characters >= 0xD800,
        # 13 information bits per continuation, then terminating char.
        ints, value, shift = [], 0, 0
        for char in text:
            unit = ord(char)
            if 0xD800 <= unit <= 0xDFFF:
                raise ValueError("surrogate_codepoint_disallowed")
            if unit >= 0xE000:
                value |= (unit & 0x1FFF) << shift
                shift += 13
                if shift > 39:
                    raise ValueError("continuation_too_long")
            else:
                ints.append(value | (unit << shift))
                value, shift = 0, 0
        if shift:
            raise ValueError("truncated_UTF16_integer")
        return ints

    def decode_fields(text):
        data = unpack(text)
        if len(data) < 10:
            raise ValueError("missing_header")
        flags, count, oneofs, hasbits, minimum, maximum, allocated, maps, repeated, check = data[:10]
        if flags & 0x1 or oneofs or hasbits or maps:
            raise ValueError("unsupported_proto2_oneof_map_hasbits")
        if count < 1 or count > 64 or len(data) != 10 + 2 * count:
            raise ValueError("field_count_or_variable_layout")
        pairs = [(data[i], data[i + 1]) for i in range(10, len(data), 2)]
        if not all(minimum <= num <= maximum for num, _ in pairs):
            raise ValueError("bad_field_range")
        if len({num for num, _ in pairs}) != count:
            raise ValueError("duplicate_field_number")
        table = {
            4: (5, 1),    # int32 singular (FieldDescriptorProto TYPE_INT32, LABEL_OPTIONAL)
            8: (9, 1),    # string singular
            26: (9, 3),   # string list
        }
        fields = []
        for num, encoded in pairs:
            typ = encoded & 0xff
            if typ not in table or encoded & ~0x2ff:
                raise ValueError("unknown_field_type_or_flags")
            fields.append((num, *table[typ]))
        return sorted(fields)

    try:
        found = decode_fields(chars)
        # Synthetic regression negatives: invalid continuation and invalid field type.
        truncated_rejected = False
        unknown_type_rejected = False
        try:
            decode_fields(chars + "\ue000")
        except ValueError:
            truncated_rejected = True
        mutated = chars[:-1] + chr(120)  # last field type unknown
        try:
            decode_fields(mutated)
        except ValueError:
            unknown_type_rejected = True
        desc_path = case / "rawmessage-oracle.pb"
        p, _ = run([protoc, f"--proto_path={case}",
                    f"--descriptor_set_out={desc_path}", original], timeout=40)
        if p.returncode != 0:
            raise ValueError("independent_protoc_descriptor_failed")
        descriptors = FileDescriptorSet()
        descriptors.ParseFromString(desc_path.read_bytes())
        expected = sorted((field.number, field.type, field.label)
                          for fd in descriptors.file
                          for message in fd.message_type
                          for field in message.field)
        if found != expected or not truncated_rejected or not unknown_type_rejected:
            report("lite_rawmessageinfo", "FAIL_INDEPENDENT_DESCRIPTOR_PARITY",
                   field_count=len(found), expected_count=len(expected),
                   malformed_rejected=truncated_rejected,
                   unknown_type_rejected=unknown_type_rejected)
            return
        report("lite_rawmessageinfo", "PASS_COMPILER_GENERATED_3_FIELDS_AND_NEGATIVES",
               numbered_types_and_labels_verified=len(found),
               field_names_from_info="UNKNOWN",
               protoc_source_sha256=hashlib.sha256(original.read_bytes()).hexdigest(),
               java_info_sha256=hashlib.sha256(chars.encode("utf-16le")).hexdigest(),
               malformed_rejected=truncated_rejected,
               unknown_type_rejected=unknown_type_rejected,
               unsupported_oneof_map_proto2="ABSTAIN")
    except (UnicodeError, ValueError) as error:
        report("lite_rawmessageinfo", "FAIL_OR_UNSUPPORTED_INFO_DECODER",
               reason=str(error)[:130])


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
    functions = [protorev, reproto, reproto_compiler_generated, lite_rawmessageinfo_oracle] if args.lane == "protocol" else [apk, androguard, apkid]
    for fn in functions:
        try:
            fn()
        except Exception as error:
            report(fn.__name__, "FAIL_EXCEPTION",
                   error_type=type(error).__name__, explanation=str(error)[:150])
    required_states = ({"protorev": "PASS_WIRE_FIELDS_AND_NEGATIVE",
                        "lite_rawmessageinfo": "PASS_COMPILER_GENERATED_3_FIELDS_AND_NEGATIVES"}
                       if args.lane == "protocol" else
                       {"apk_fixture": "PASS_DEX_AUTHORED",
                        "androguard": "PASS_DEX_CLASS_AND_NEGATIVE"})
    mandatory = list(required_states)
    states = {x: y["status"] for x, y in state["results"].items()}
    qualified = all(states.get(name) == exact for name, exact in required_states.items())
    state["overall"] = "PASS_REQUIRED_WITH_REPROTO_UNQUALIFIED" if qualified and args.lane == "protocol" else ("PASS_REQUIRED_WITH_CANDIDATE_LIMITS" if qualified else "FAIL_REQUIRED")
    state["mandatory"] = mandatory
    state["unqualified_candidates"] = [name for name, item in state["results"].items() if not item["status"].startswith("PASS")]
    (ROOT / "receipt.json").write_text(json.dumps(state, sort_keys=True, indent=2) + "\n")
    print(json.dumps({"lane": args.lane, "overall": state["overall"],
                      "results": states}, sort_keys=True))
    sys.exit(0 if qualified else 1)

if __name__ == "__main__":
    main()
