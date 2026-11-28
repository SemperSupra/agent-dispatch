#!/usr/bin/env python3
"""Independent byte/effect comparator for the dos2unix Windows/Wine exercise.

No reference implementation or replacement code is imported. The frozen case
manifest is the input authority; observed reference receipts are the behavioral
oracle. A green behavioral comparison and complete Product 1 observation are
reported separately. Missing evidence never earns full qualification.

Required case observer fields:
  executable_sha256: actual launched PE digest
  capture_complete: bool
  deadline_exceeded: bool
  debug_available: bool (actual debugger capability observation, not a guess)
  receipt: complete cre-win32-observer-v1 receipt, independently checked below

Optional observer fields truncated/stdout_truncated/stderr_truncated/errors
are checked when present. Extra observer evidence is preserved in input reports.
Inventory paths are relative to the case directory; its root is omitted.
files_after contains raw hexadecimal bytes for every after-inventory file.

Exit 0: whole corpus accepted. Exit 1: a mismatch or incomplete qualification.
Exit 2: input/manifest could not be loaded. JSON reports are retained in all
cases where the output directory can be created.
"""

from __future__ import annotations

import argparse
import copy
import hashlib
import json
import math
from pathlib import Path, PurePosixPath
import re
import sys


SCHEMA = "cre.windows-re.validation.v1"
CASE_SCHEMA = "cre.windows-re.validation-cases.v1"
FROZEN_CASE_SHA256 = "81d8f3e0f893888b68d0234da7ec0c8ec7a046c14d92cafe873609da4be312ab"
ARCHIVE_SHA256 = "8c1af6e366e641a859a1d58457663aedd1f3b4aae37e67621449beef145cf934"
HEX64 = re.compile(r"^[0-9a-f]{64}$")
HEX = re.compile(r"^(?:[0-9a-fA-F]{2})*$")
# An explicit allowlist. Only a diagnostic line's leading program-name field
# is normalized, never text elsewhere in a diagnostic or a supplied filename.
DIAGNOSTIC_PROGRAM_NAMES = (
    b"dos2unix", b"dos2unix.exe", b"cre-dos2unix", b"cre-dos2unix.exe",
)
PROGRAM_PREFIX = re.compile(
    rb"(?m)^(?:" + b"|".join(re.escape(n) for n in DIAGNOSTIC_PROGRAM_NAMES) + rb"):"
)
CANCEL_EXIT = 0xC000013A
CONTROL_EXCEPTION = 0xE0421001
ACTUATOR_INPUT = b"owned\r\ncontrol\r\n"
ACTUATOR_OUTPUT = b"owned\ncontrol\n"


def sha(data):
    return hashlib.sha256(data).hexdigest()


def int_value(value):
    return isinstance(value, int) and not isinstance(value, bool)


def mapping(value):
    return value if isinstance(value, dict) else {}


def sequence(value):
    return value if isinstance(value, list) else []


def issue(code, detail):
    return {"code": code, "detail": detail}


def valid_digest(value):
    return isinstance(value, str) and bool(HEX64.fullmatch(value))


def nonnegative_integer(value):
    return int_value(value) and value >= 0


def address(value):
    if not isinstance(value, str) or not re.fullmatch(r"0x[0-9a-fA-F]+", value):
        raise ValueError("expected hexadecimal address")
    number = int(value, 16)
    if number >= 1 << 64:
        raise ValueError("address exceeds uint64")
    return number


def decode_hex(value):
    if not isinstance(value, str) or not HEX.fullmatch(value):
        raise ValueError("expected an even-length hexadecimal string")
    return bytes.fromhex(value)


def safe_relative_path(value):
    if not isinstance(value, str) or not value or "\\" in value or "\x00" in value:
        return False
    path = PurePosixPath(value)
    return (
        not path.is_absolute() and value == str(path) and
        all(p not in (".", "..") and ":" not in p for p in path.parts)
    )


def file_signature(data):
    return {"kind": "file", "sha256": sha(data), "bytes": len(data)}


def inventory_signature(inventory):
    result = {}
    for path, entry in inventory.items():
        result[path] = (
            {"kind": "directory"} if entry.get("kind") == "directory"
            else {"kind": entry.get("kind"), "sha256": entry.get("sha256"),
                  "bytes": entry.get("bytes")}
        )
    return result


def expected_before(case):
    inventory = {path: {"kind": "directory"} for path in case.get("dirs", [])}
    files = list(case.get("files", []))
    generator = case.get("filegenerator")
    if generator is not None:
        data = decode_hex(generator["pattern_hex"]) * generator["repeat"]
        data += decode_hex(generator["suffix_hex"])
        files.append({"path": generator["path"], "data_hex": data.hex()})
    for entry in files:
        path = entry["path"]
        inventory[path] = file_signature(decode_hex(entry["data_hex"]))
        parent = PurePosixPath(path).parent
        while str(parent) != ".":
            inventory[str(parent)] = {"kind": "directory"}
            parent = parent.parent
    for path in list(inventory):
        parent = PurePosixPath(path).parent
        while str(parent) != ".":
            inventory.setdefault(str(parent), {"kind": "directory"})
            parent = parent.parent
    return inventory


def validate_inventory(value, label):
    problems = []
    if not isinstance(value, dict):
        return [issue("INVALID_INVENTORY", f"{label} must be an object")]
    for path, entry in value.items():
        if not safe_relative_path(path):
            problems.append(issue("INVALID_INVENTORY_PATH", f"{label}: {path!r}"))
        if not isinstance(entry, dict) or entry.get("kind") not in ("file", "directory"):
            problems.append(issue("INVALID_INVENTORY_ENTRY", f"{label}: {path!r}"))
            continue
        if entry["kind"] == "file":
            if not valid_digest(entry.get("sha256")):
                problems.append(issue("INVALID_FILE_DIGEST", f"{label}: {path}"))
            if not int_value(entry.get("bytes")) or entry["bytes"] < 0:
                problems.append(issue("INVALID_FILE_LENGTH", f"{label}: {path}"))
    return problems


def raw_observer_issues(record, expected_mode, control_kind=None):
    """Check the C observer's facts; do not trust adapter classification alone."""
    problems = []
    observer = record.get("observer", {})
    receipt = observer.get("receipt") if isinstance(observer, dict) else None
    if not isinstance(receipt, dict) or receipt.get("schema") != "cre-win32-observer-v1":
        return [issue("RAW_OBSERVER_UNAVAILABLE", "complete cre-win32-observer-v1 receipt required")]
    if record.get("mode") != expected_mode or receipt.get("mode") != expected_mode:
        problems.append(issue("OBSERVER_MODE_MISMATCH", {"expected": expected_mode,
            "row": record.get("mode"), "receipt": receipt.get("mode")}))
    for field in ("observer_ok", "created"):
        if receipt.get(field) is not True:
            problems.append(issue("RAW_OBSERVER_INCOMPLETE", field))
    expected_limits = {"timed_out": control_kind == "sleep", "output_overflow": control_kind == "stdout"}
    for field, expected in expected_limits.items():
        if receipt.get(field) is not expected:
            problems.append(issue("RAW_OBSERVER_INCOMPLETE", field))
    command = receipt.get("command", {})
    intended = record.get("args")
    expected_arguments = ([arg.encode("utf-16le", errors="surrogatepass").hex() for arg in intended]
                          if isinstance(intended, list) and all(isinstance(arg, str) for arg in intended) else None)
    if (not isinstance(command, dict) or command.get("source") != "observer_wmain_argv" or
            command.get("target_crt_arguments_observed") is not False or
            command.get("arguments_truncated") is not False or expected_arguments is None or
            command.get("arguments_count") != len(expected_arguments) or
            command.get("arguments_utf16le_hex") != expected_arguments or
            command.get("utf16_code_units_limit") != 32766):
        problems.append(issue("OBSERVED_ARGUMENT_MISMATCH", {
            "scope": "actual host-to-observer wmain arguments, excluding target executable and terminating NUL",
            "expected_utf16le_hex": expected_arguments, "observed": command}))
    error = receipt.get("observer_error", {})
    if not isinstance(error, dict) or error.get("win32") != 0 or error.get("operation") != "":
        problems.append(issue("RAW_OBSERVER_ERROR", error))
    if observer.get("exit_code") != 0:
        problems.append(issue("OBSERVER_PROCESS_EXIT", "native observer did not report successful exit"))
    target_exit = receipt.get("target_exit", {})
    if (not isinstance(target_exit, dict) or target_exit.get("available") is not True or
            not nonnegative_integer(target_exit.get("code")) or target_exit.get("code", 1 << 32) >= 1 << 32):
        problems.append(issue("RAW_TARGET_EXIT_UNAVAILABLE", "available uint32 target exit required"))
    elif target_exit["code"] != record.get("exit_code"):
        problems.append(issue("TARGET_EXIT_MISMATCH", "adapter exit differs from raw debugger exit"))
    cleanup = receipt.get("cleanup", {})
    for field in ("exit_event_seen", "process_signaled", "complete"):
        if not isinstance(cleanup, dict) or cleanup.get(field) is not True:
            problems.append(issue("RAW_CLEANUP_INCOMPLETE", field))
    if isinstance(cleanup, dict) and cleanup.get("descendant_retirement") != "unknown":
        problems.append(issue("UNSUPPORTED_DESCENDANT_CLAIM", "this observer qualifies only the immediate child"))
    streams = receipt.get("streams", {})
    for kind in ("stdout", "stderr"):
        stream = streams.get(kind) if isinstance(streams, dict) else None
        if not isinstance(stream, dict):
            problems.append(issue("RAW_STREAM_UNAVAILABLE", kind))
            continue
        expected_overflow = control_kind == "stdout" and kind == "stdout"
        if stream.get("eof") is not True or stream.get("overflow") is not expected_overflow or stream.get("error") != 0:
            problems.append(issue("RAW_STREAM_INCOMPLETE", kind))
        seen, retained = stream.get("bytes_seen"), stream.get("bytes_retained")
        try:
            captured = len(decode_hex(record.get(kind + "_hex")))
        except ValueError:
            captured = None
        counts_match = (nonnegative_integer(seen) and nonnegative_integer(retained) and
                        retained == captured and (seen > retained if expected_overflow else seen == retained))
        if not counts_match:
            problems.append(issue("RAW_STREAM_LENGTH_MISMATCH", {
                "stream": kind, "seen": seen, "retained": retained, "captured": captured}))
    image = receipt.get("image", {})
    debug = receipt.get("debug", {})
    debug_available = (receipt.get("created") is True and isinstance(image, dict) and
                       image.get("available") is True and isinstance(debug, dict) and
                       debug.get("create_event_seen") is True)
    if not debug_available:
        problems.append(issue("DEBUG_UNAVAILABLE", "raw create event and mapped-image observation required"))
    if observer.get("debug_available") is not debug_available:
        problems.append(issue("DEBUG_SUMMARY_MISMATCH", "adapter debug_available disagrees with raw receipt"))
    if isinstance(image, dict) and image.get("available") is True:
        if (image.get("source") != "CREATE_PROCESS_DEBUG_EVENT_and_ReadProcessMemory" or
                image.get("machine") != 0x8664 or image.get("optional_magic") != 0x20B or image.get("error") != 0):
            problems.append(issue("MAPPED_IMAGE_INVALID", "expected observed PE32+ x64 image"))
        try:
            base, entry = address(image.get("base_hex")), address(image.get("entry_address_hex"))
            rva, size = image.get("entry_rva"), image.get("image_size")
            if not nonnegative_integer(rva) or not nonnegative_integer(size) or not 0 < rva < size or entry != base + rva:
                problems.append(issue("MAPPED_ENTRY_MISMATCH", "entry address must equal actual mapped base plus in-image RVA"))
        except ValueError as exc:
            problems.append(issue("MAPPED_IMAGE_INVALID", str(exc)))
    events = receipt.get("events")
    total, dropped = receipt.get("events_total"), receipt.get("events_dropped")
    if (not isinstance(events, list) or not nonnegative_integer(total) or
            not nonnegative_integer(dropped) or dropped != 0 or total != len(events)):
        problems.append(issue("DEBUG_EVENTS_INCOMPLETE", {"total": total, "dropped": dropped,
            "retained": len(events) if isinstance(events, list) else None}))
    elif not events or any(not isinstance(event, dict) for event in events):
        problems.append(issue("DEBUG_EVENTS_INVALID", "nonempty typed event list required"))
    else:
        pid = receipt.get("pid")
        if not nonnegative_integer(pid) or pid == 0 or any(event.get("process_id") != pid for event in events):
            problems.append(issue("DEBUG_EVENT_PROCESS_MISMATCH", "all events must belong to observed child PID"))
        if [event.get("sequence") for event in events] != list(range(1, len(events) + 1)):
            problems.append(issue("DEBUG_EVENT_SEQUENCE_MISMATCH", "retained events must have consecutive sequence numbers"))
        if any(event.get("continued") is not True or event.get("continue_error") != 0 for event in events):
            problems.append(issue("DEBUG_CONTINUATION_INCOMPLETE", "every retained debug event must be successfully continued"))
        creates = [event for event in events if event.get("type") == "create_process"]
        exits = [event for event in events if event.get("type") == "exit_process"]
        if len(creates) != 1 or len(exits) != 1 or events[0].get("type") != "create_process" or events[-1].get("type") != "exit_process":
            problems.append(issue("DEBUG_LIFECYCLE_INCOMPLETE", "one create followed by one final exit required"))
        elif exits[0].get("code") != record.get("exit_code"):
            problems.append(issue("DEBUG_EXIT_EVENT_MISMATCH", "exit event and adapter exit disagree"))
        if not isinstance(debug, dict) or debug.get("successful_continuations") != len(events):
            problems.append(issue("DEBUG_CONTINUATION_COUNT_MISMATCH", "summary count differs from retained events"))
    if expected_mode == "run":
        for field in ("cancelled", "abort_before_first_continue"):
            if receipt.get(field) is not False:
                problems.append(issue("UNEXPECTED_RUNTIME_INTERVENTION", field))
        breakpoint = receipt.get("breakpoint", {})
        termination = receipt.get("termination", {})
        if not isinstance(breakpoint, dict) or breakpoint.get("requested") is not False:
            problems.append(issue("UNEXPECTED_RUNTIME_INTERVENTION", "breakpoint requested during baseline"))
        if control_kind not in ("sleep", "stdout") and (not isinstance(termination, dict) or termination.get("attempted") is not False):
            problems.append(issue("UNEXPECTED_RUNTIME_INTERVENTION", "termination attempted during baseline"))
    return problems


def record_issues(record, report, case, expected_mode="run"):
    """Validate evidence independently of whether behavior matches another run."""
    problems = []
    if record is None:
        return [issue("MISSING_CASE", case["id"])]
    if record.get("args") != case["args"]:
        problems.append(issue("ARGUMENT_MISMATCH", "argument vector differs from frozen case"))
    if not int_value(record.get("exit_code")):
        problems.append(issue("EXIT_UNAVAILABLE", "exit_code must be an observed integer"))
    duration = record.get("duration_ms")
    if (not isinstance(duration, (int, float)) or isinstance(duration, bool) or
            not math.isfinite(duration) or duration < 0):
        problems.append(issue("DURATION_UNAVAILABLE", "duration_ms must be finite and nonnegative"))
    for field in ("stdout_hex", "stderr_hex"):
        try:
            decode_hex(record.get(field))
        except ValueError as exc:
            problems.append(issue("CAPTURE_UNAVAILABLE", f"{field}: {exc}"))
    observer = record.get("observer")
    if not isinstance(observer, dict):
        observer = {}
        problems.append(issue("OBSERVER_UNAVAILABLE", "observer must be an object"))
    expected_digest = report.get(
        "target_sha256" if record.get("subject") == "reference" else "candidate_sha256"
    )
    if not valid_digest(observer.get("executable_sha256")):
        problems.append(issue("LAUNCH_DIGEST_UNAVAILABLE", "observer.executable_sha256 missing/invalid"))
    elif observer["executable_sha256"] != expected_digest:
        problems.append(issue("DIGEST_MISMATCH", "launched PE differs from report subject digest"))
    if observer.get("capture_complete") is not True:
        problems.append(issue("CAPTURE_INCOMPLETE", "capture_complete is not true"))
    if observer.get("deadline_exceeded") is not False:
        problems.append(issue("DEADLINE_EXCEEDED_OR_UNKNOWN", "deadline_exceeded is not false"))
    if observer.get("debug_available") is not True:
        problems.append(issue("DEBUG_UNAVAILABLE", "debug_available is not true"))
    for field in ("truncated", "stdout_truncated", "stderr_truncated"):
        if observer.get(field) is True:
            problems.append(issue("CAPTURE_TRUNCATED", field))
        elif field in observer and not isinstance(observer[field], bool):
            problems.append(issue("CAPTURE_COMPLETENESS_UNKNOWN", field))
    if observer.get("errors"):
        problems.append(issue("OBSERVER_ERROR", observer["errors"]))
    problems += raw_observer_issues(record, expected_mode)
    before_problems = validate_inventory(record.get("before"), "before")
    after_problems = validate_inventory(record.get("after"), "after")
    problems += before_problems + after_problems
    if not before_problems and inventory_signature(record["before"]) != expected_before(case):
        problems.append(issue("FIXTURE_MISMATCH", "before inventory differs from frozen fixture"))
    files_after = record.get("files_after")
    if not isinstance(files_after, dict):
        problems.append(issue("AFTER_BYTES_UNAVAILABLE", "files_after must contain every after-file"))
    elif not after_problems:
        file_paths = {p for p, e in record["after"].items() if e["kind"] == "file"}
        if set(files_after) != file_paths:
            problems.append(issue("AFTER_BYTE_PATHS_MISMATCH", {
                "missing": sorted(file_paths - set(files_after)),
                "unexpected": sorted(set(files_after) - file_paths),
            }))
        for path in file_paths & set(files_after):
            try:
                signature = file_signature(decode_hex(files_after[path]))
                actual = inventory_signature({path: record["after"][path]})[path]
                if signature != actual:
                    problems.append(issue("AFTER_BYTES_DIGEST_MISMATCH", path))
            except ValueError as exc:
                problems.append(issue("AFTER_BYTES_INVALID", f"{path}: {exc}"))
    return problems


def normalize_stderr(raw):
    normalized, count = PROGRAM_PREFIX.subn(b"<PROGRAM>:", raw)
    return normalized, {"program_prefix_replacements": count, "temporary_name_replacements": 0}


def diagnostic_class(raw):
    lower = raw.lower()
    if not raw:
        return "empty"
    if b"usage:" in lower or b"invalid option" in lower or b"unknown option" in lower:
        return "usage-or-option"
    if b"binary" in lower and (b"skip" in lower or b"symbol" in lower):
        return "binary-diagnostic"
    if any(term in lower for term in (b"error", b"failed", b"cannot", b"no such file")):
        return "error-diagnostic"
    if b"converting file" in lower:
        return "conversion-notice"
    return "other"


def persistent_changes(record):
    before = inventory_signature(record["before"])
    after = inventory_signature(record["after"])
    return sorted(p for p in set(before) | set(after) if before.get(p) != after.get(p))


def first_difference(left, right):
    position = next((i for i, (a, b) in enumerate(zip(left, right)) if a != b), None)
    if position is None and len(left) != len(right):
        position = min(len(left), len(right))
    if position is None:
        return None
    start = max(0, position - 8)
    return {"offset": position, "left_length": len(left), "right_length": len(right),
            "left_context_hex": left[start:position + 9].hex(),
            "right_context_hex": right[start:position + 9].hex()}


def behavior_comparison(left, right):
    differences = []
    if left["exit_code"] != right["exit_code"]:
        differences.append({"field": "exit_code", "left": left["exit_code"], "right": right["exit_code"]})
    stdout_left = decode_hex(left["stdout_hex"])
    stdout_right = decode_hex(right["stdout_hex"])
    if stdout_left != stdout_right:
        differences.append({"field": "stdout", **first_difference(stdout_left, stdout_right)})
    raw_left, raw_right = decode_hex(left["stderr_hex"]), decode_hex(right["stderr_hex"])
    stderr_left, norm_left = normalize_stderr(raw_left)
    stderr_right, norm_right = normalize_stderr(raw_right)
    stderr = {
        "raw_equal": raw_left == raw_right, "normalized_equal": stderr_left == stderr_right,
        "left": {"raw_hex": raw_left.hex(), "sha256": sha(raw_left),
                 "class": diagnostic_class(raw_left), "normalization": norm_left},
        "right": {"raw_hex": raw_right.hex(), "sha256": sha(raw_right),
                  "class": diagnostic_class(raw_right), "normalization": norm_right},
    }
    if stderr_left != stderr_right:
        differences.append({"field": "stderr", **first_difference(stderr_left, stderr_right)})
    after_left, after_right = inventory_signature(left["after"]), inventory_signature(right["after"])
    for path in sorted(set(after_left) | set(after_right)):
        if after_left.get(path) != after_right.get(path):
            differences.append({"field": "after_inventory", "path": path,
                                "left": after_left.get(path), "right": after_right.get(path)})
    for path in sorted(set(left["files_after"]) & set(right["files_after"])):
        data_left = decode_hex(left["files_after"][path])
        data_right = decode_hex(right["files_after"][path])
        if data_left != data_right:
            differences.append({"field": "file_bytes", "path": path,
                                **first_difference(data_left, data_right)})
    touched_left, touched_right = persistent_changes(left), persistent_changes(right)
    if touched_left != touched_right:
        differences.append({"field": "persistent_effect_paths", "left": touched_left, "right": touched_right})
    return {
        "match": not differences, "differences": differences, "stderr": stderr,
        "persistent_effect_paths": {"left": touched_left, "right": touched_right},
    }


def load_report(path, expected_platform, cases):
    data = json.loads(path.read_text(encoding="utf-8"))
    problems = []
    if not isinstance(data, dict):
        return {"platform": expected_platform}, {}, [issue("INVALID_REPORT", "report must be an object")]
    if not isinstance(data.get("schema"), str) or not data["schema"]:
        problems.append(issue("SCHEMA_UNAVAILABLE", "report schema is required"))
    if data.get("platform") != expected_platform:
        problems.append(issue("PLATFORM_MISMATCH", {"expected": expected_platform, "actual": data.get("platform")}))
    for key in ("target_sha256", "candidate_sha256"):
        if not valid_digest(data.get(key)):
            problems.append(issue("INVALID_REPORT_DIGEST", key))
    if valid_digest(data.get("target_sha256")) and data.get("target_sha256") == data.get("candidate_sha256"):
        problems.append(issue("IDENTICAL_SUBJECT_DIGESTS", "reference and independent reconstruction have identical PE digests"))
    records = data.get("cases")
    index = {}
    if not isinstance(records, list):
        problems.append(issue("CASE_LIST_UNAVAILABLE", "cases must be an array"))
        records = []
    ids = {case["id"] for case in cases}
    for record in records:
        if not isinstance(record, dict):
            problems.append(issue("INVALID_CASE_RECORD", "case record must be an object"))
            continue
        key = (record.get("id"), record.get("subject"))
        if not isinstance(key[0], str) or not isinstance(key[1], str):
            problems.append(issue("INVALID_CASE_KEY", "id and subject must be strings"))
        elif key[0] not in ids or key[1] not in ("reference", "candidate"):
            problems.append(issue("UNEXPECTED_CASE_RECORD", list(key)))
        elif key in index:
            problems.append(issue("DUPLICATE_CASE_RECORD", list(key)))
        else:
            index[key] = record
    return data, index, problems


def compare_pair(name, left_platform, left_subject, right_platform, right_subject,
                 cases, reports, indexes, report_problems):
    rows = []
    globals_ = report_problems[left_platform] + report_problems[right_platform]
    for case in cases:
        left = indexes[left_platform].get((case["id"], left_subject))
        right = indexes[right_platform].get((case["id"], right_subject))
        left_problems = record_issues(left, reports[left_platform], case)
        right_problems = record_issues(right, reports[right_platform], case)
        # Only a missing debug capability allows a still meaningful separate
        # behavioral result; capture/identity/fixture uncertainty invalidates it.
        behavior_safe = all(
            item["code"] == "DEBUG_UNAVAILABLE" for item in left_problems + right_problems
        ) and not globals_
        behavior = behavior_comparison(left, right) if behavior_safe else None
        complete = not (left_problems or right_problems or globals_)
        accepted = complete and behavior is not None and behavior["match"]
        if accepted:
            classification = "PASS_BOUNDED"
        elif not complete:
            classification = "EVIDENCE_INCOMPLETE"
        elif left_platform != right_platform:
            classification = "PLATFORM_DIFFERENCE"
        else:
            classification = "RECONSTRUCTION_MISMATCH"
        rows.append({
            "id": case["id"], "group": case["group"], "challenge": case["challenge"],
            "accepted": accepted, "classification": classification,
            "behavior_match": behavior["match"] if behavior is not None else None,
            "exit_and_persistent_effects_match": (
                all(difference["field"] in ("stdout", "stderr") for difference in behavior["differences"])
                if behavior is not None else None
            ),
            "observation_complete": complete,
            "left_evidence_issues": left_problems, "right_evidence_issues": right_problems,
            "comparison": behavior,
        })
    primary = [r for r in rows if not r["challenge"]]
    challenge = [r for r in rows if r["challenge"]]
    return {
        "schema": SCHEMA, "name": name,
        "left": {"platform": left_platform, "subject": left_subject},
        "right": {"platform": right_platform, "subject": right_subject},
        "accepted": bool(rows) and all(r["accepted"] for r in rows),
        "primary_contract_accepted": bool(primary) and all(r["accepted"] for r in primary),
        "challenge_contract_accepted": bool(challenge) and all(r["accepted"] for r in challenge),
        "behavior_matches": sum(r["behavior_match"] is True for r in rows),
        "exit_and_persistent_effects_matches": sum(r["exit_and_persistent_effects_match"] is True for r in rows),
        "exit_and_persistent_effects_scope": (
            "Exact exit code, retained file bytes, after inventory and persistent-effect paths; "
            "excludes stdout/stderr. This count is not strict conformance or observation qualification."
        ),
        "accepted_cases": sum(r["accepted"] for r in rows), "case_count": len(rows),
        "report_issues": globals_, "cases": rows,
    }


def negative_controls(cases, reports, indexes):
    for platform in ("windows", "wine"):
        for case in cases:
            record = indexes[platform].get((case["id"], "reference"))
            problems = record_issues(record, reports[platform], case)
            if any(p["code"] != "DEBUG_UNAVAILABLE" for p in problems):
                continue
            if not record["files_after"]:
                continue
            baseline = behavior_comparison(record, record)
            altered = copy.deepcopy(record)
            output_paths = [p for p in altered["files_after"] if p not in expected_before(case)]
            path = sorted(output_paths or altered["files_after"])[0]
            changed = decode_hex(altered["files_after"][path]) + b"\xff"
            altered["files_after"][path] = changed.hex()
            altered["after"][path] = file_signature(changed)
            result = behavior_comparison(record, altered)
            tamper_pass = baseline["match"] and not result["match"] and any(
                d["field"] == "file_bytes" for d in result["differences"]
            )
            digest_record = copy.deepcopy(record)
            original_digest = digest_record["observer"]["executable_sha256"]
            digest_record["observer"]["executable_sha256"] = "0" * 64 if original_digest != "0" * 64 else "1" * 64
            digest_problems = record_issues(digest_record, reports[platform], case)
            digest_pass = any(p["code"] == "DIGEST_MISMATCH" for p in digest_problems)
            return {
                "schema": SCHEMA, "accepted": tamper_pass and digest_pass,
                "basis": {"platform": platform, "case": case["id"], "subject": "reference"},
                "positive_self_comparison_passed": baseline["match"],
                "controls": [
                    {"name": "tampered-output", "passed": tamper_pass, "path": path,
                     "mutation": "append ff and recompute receipt digest/length; compare actual bytes",
                     "detected_differences": result["differences"]},
                    {"name": "launch-digest-mismatch", "passed": digest_pass,
                     "mutation": "replace observed launched PE digest with another valid SHA-256",
                     "detected_issues": digest_problems},
                ],
            }
    return {"schema": SCHEMA, "accepted": False, "classification": "NOT_RUN",
            "reason": "No internally valid reference receipt with retained file bytes for negative controls.",
            "controls": []}


def actuator_checks(reports):
    case = {"id": "actuator-entry", "args": ["-n", "input.txt", "output.txt"],
            "files": [{"path": "input.txt", "data_hex": ACTUATOR_INPUT.hex()}]}
    baseline = expected_before(case)
    completed = {**baseline, "output.txt": file_signature(ACTUATOR_OUTPUT)}
    expected_keys = {(subject, mode) for subject in ("reference", "candidate")
                     for mode in ("breakpoint", "abort", "run")}
    rows, global_issues = [], []
    for platform, report in reports.items():
        records = report.get("actuators")
        index = {}
        if not isinstance(records, list):
            global_issues.append(issue("ACTUATOR_LIST_UNAVAILABLE", platform))
            records = []
        for record in records:
            if not isinstance(record, dict):
                global_issues.append(issue("INVALID_ACTUATOR_RECORD", platform))
                continue
            key = (record.get("subject"), record.get("mode"))
            if not all(isinstance(part, str) for part in key) or key not in expected_keys:
                global_issues.append(issue("UNEXPECTED_ACTUATOR_RECORD", platform))
            elif key in index:
                global_issues.append(issue("DUPLICATE_ACTUATOR_RECORD", {"platform": platform, "key": list(key)}))
            else:
                index[key] = record
        for subject, mode in sorted(expected_keys):
            record = index.get((subject, mode))
            problems = record_issues(record, report, case, mode)
            if record is not None and record.get("id") != "actuator-entry":
                problems.append(issue("ACTUATOR_CASE_ID_MISMATCH", record.get("id")))
            if record is not None and not problems:
                receipt = record["observer"]["receipt"]
                if mode == "abort":
                    termination = receipt.get("termination", {})
                    if (receipt.get("cancelled") is not True or receipt.get("abort_before_first_continue") is not True or
                            not isinstance(termination, dict) or termination.get("attempted") is not True or
                            termination.get("succeeded") is not True or termination.get("error") != 0 or
                            termination.get("reason") != "operator_abort" or record["exit_code"] != CANCEL_EXIT):
                        problems.append(issue("ABORT_NOT_PROVEN", "owned termination before first continuation and cancellation exit required"))
                    if (inventory_signature(record["after"]) != baseline or
                            record["files_after"] != {"input.txt": ACTUATOR_INPUT.hex()} or
                            record["stdout_hex"] != "" or record["stderr_hex"] != ""):
                        problems.append(issue("ABORT_EFFECT_MISMATCH", "entry abort must preserve fixture with no target output"))
                else:
                    if (record["exit_code"] != 0 or inventory_signature(record["after"]) != completed or
                            record["files_after"] != {"input.txt": ACTUATOR_INPUT.hex(), "output.txt": ACTUATOR_OUTPUT.hex()}):
                        problems.append(issue("ACTUATOR_RECOVERY_EFFECT_MISMATCH", "normal conversion must preserve input and produce exact recovered output"))
                    if mode == "breakpoint":
                        bp = receipt.get("breakpoint", {})
                        required = ("requested", "install_attempted", "installed", "hit", "original_known",
                                    "install_readback", "context_read", "byte_restored", "byte_restore_verified",
                                    "install_protection_restored", "protection_restored", "context_rewound", "continued")
                        if not isinstance(bp, dict) or any(bp.get(field) is not True for field in required):
                            problems.append(issue("BREAKPOINT_NOT_PROVEN", "complete installation, hit, context and restoration observations required"))
                        elif bp.get("error") != 0 or bp.get("operation") != "" or not nonnegative_integer(bp.get("original_byte")) or bp["original_byte"] > 255:
                            problems.append(issue("BREAKPOINT_ERROR", "byte or operation/error receipt invalid"))
                        else:
                            try:
                                entry = address(receipt["image"]["entry_address_hex"])
                                if address(bp.get("rip_before_hex")) != entry + 1 or address(bp.get("rip_after_hex")) != entry:
                                    problems.append(issue("BREAKPOINT_REGISTER_MISMATCH", "INT3 RIP must be rewound by one byte to mapped entry"))
                                hit_events = [event for event in receipt["events"]
                                              if event.get("type") == "exception" and event.get("code") == 0x80000003 and
                                              event.get("first_chance") == 1 and address(event.get("address_hex")) == entry]
                                if (len(hit_events) != 1 or hit_events[0].get("thread_id") != bp.get("thread_id") or
                                        hit_events[0].get("continuation_status") != 0x00010002 or hit_events[0].get("continued") is not True):
                                    problems.append(issue("BREAKPOINT_EVENT_MISMATCH", "entry hit must match retained first-chance INT3 event and continued thread"))
                            except (ValueError, KeyError) as exc:
                                problems.append(issue("BREAKPOINT_REGISTER_MISMATCH", str(exc)))
                        termination = receipt.get("termination", {})
                        if receipt.get("cancelled") is not False or not isinstance(termination, dict) or termination.get("attempted") is not False:
                            problems.append(issue("BREAKPOINT_UNEXPECTED_TERMINATION", "recovered breakpoint run must complete without termination"))
            independent_pass = not problems
            if record is not None and record.get("oracle_passed") is not independent_pass:
                problems.append(issue("DRIVER_ACTUATOR_ORACLE_DISAGREES", {
                    "driver": record.get("oracle_passed"), "independent": independent_pass}))
            rows.append({"platform": platform, "subject": subject, "mode": mode,
                         "accepted": not problems, "issues": problems})
    return {"schema": SCHEMA, "accepted": not global_issues and all(row["accepted"] for row in rows),
            "scope": "entry breakpoint with exact byte/register restoration, owned pre-entry abort, and subsequent baseline recovery",
            "issues": global_issues, "cases": rows}


def observer_control_checks(reports):
    """Synthetic sensor controls stay separate from recovered-program cases."""
    rows, global_issues = [], []
    kinds = {"control-sleep": "sleep", "control-stdout": "stdout", "control-exception": "exception"}
    for platform, report in reports.items():
        executables = mapping(mapping(report.get("package_manifest")).get("executables"))
        declared = mapping(executables.get("observer-control")).get("sha256")
        if not valid_digest(declared):
            global_issues.append(issue("CONTROL_IMAGE_DIGEST_UNAVAILABLE", platform))
        records = report.get("observer_controls")
        index = {}
        if not isinstance(records, list):
            global_issues.append(issue("OBSERVER_CONTROLS_UNAVAILABLE", platform))
            records = []
        for record in records:
            key = record.get("id") if isinstance(record, dict) else None
            if not isinstance(key, str) or key not in kinds:
                global_issues.append(issue("UNEXPECTED_OBSERVER_CONTROL", platform))
            elif key in index:
                global_issues.append(issue("DUPLICATE_OBSERVER_CONTROL", {"platform": platform, "id": key}))
            else:
                index[key] = record
        for cid, kind in kinds.items():
            record = index.get(cid)
            problems = []
            if record is None:
                problems.append(issue("MISSING_OBSERVER_CONTROL", cid))
            else:
                if (record.get("subject") != "observer-control" or record.get("synthetic_control") is not True or
                        record.get("args") != [kind] or record.get("mode") != "run"):
                    problems.append(issue("CONTROL_IDENTITY_MISMATCH", cid))
                observer = record.get("observer", {})
                if not isinstance(observer, dict):
                    observer = {}
                if not valid_digest(declared) or observer.get("executable_sha256") != declared:
                    problems.append(issue("CONTROL_LAUNCH_DIGEST_MISMATCH", cid))
                for field, expected in (("capture_complete", kind == "exception"),
                                        ("deadline_exceeded", kind == "sleep"),
                                        ("truncated", kind == "stdout"), ("debug_available", True)):
                    if observer.get(field) is not expected:
                        problems.append(issue("CONTROL_SUMMARY_MISMATCH", {"field": field, "expected": expected}))
                if observer.get("errors") != []:
                    problems.append(issue("CONTROL_ADAPTER_ERROR", observer.get("errors")))
                problems += raw_observer_issues(record, "run", kind)
                if record.get("before") != {} or record.get("after") != {} or record.get("files_after") != {}:
                    problems.append(issue("CONTROL_FILE_EFFECT_MISMATCH", "synthetic controls must leave owned directory empty"))
                try:
                    stdout, stderr = decode_hex(record.get("stdout_hex")), decode_hex(record.get("stderr_hex"))
                except ValueError as exc:
                    problems.append(issue("CONTROL_OUTPUT_UNAVAILABLE", str(exc)))
                    stdout, stderr = None, None
                if stderr != b"" or stdout != (b"X" * 65536 if kind == "stdout" else b""):
                    problems.append(issue("CONTROL_OUTPUT_MISMATCH", "expected bounded X bytes or no output/sentinel"))
                receipt = observer.get("receipt", {})
                if not isinstance(receipt, dict):
                    receipt = {}
                termination = receipt.get("termination", {})
                if not isinstance(termination, dict):
                    termination = {}
                bounds = receipt.get("bounds", {})
                if not isinstance(bounds, dict):
                    bounds = {}
                if bounds.get("stream_bytes_each") != 65536:
                    problems.append(issue("CONTROL_STREAM_BOUND_MISMATCH", bounds.get("stream_bytes_each")))
                if kind == "sleep":
                    if (bounds.get("timeout_ms") != 100 or record.get("exit_code") != CANCEL_EXIT or
                            termination.get("attempted") is not True or termination.get("succeeded") is not True or
                            termination.get("error") != 0 or termination.get("reason") != "timeout"):
                        problems.append(issue("DEADLINE_CONTROL_NOT_PROVEN", "100 ms deadline, owned cancellation exit and complete termination required"))
                elif kind == "stdout":
                    stream = mapping(mapping(receipt.get("streams")).get("stdout"))
                    seen, retained = stream.get("bytes_seen"), stream.get("bytes_retained")
                    if not nonnegative_integer(seen) or not 65536 < seen <= 81920 or retained != 65536:
                        problems.append(issue("OUTPUT_LIMIT_CONTROL_NOT_PROVEN", {"seen": seen, "retained": retained}))
                    if record.get("exit_code") not in (0, CANCEL_EXIT):
                        problems.append(issue("OUTPUT_LIMIT_EXIT_UNEXPECTED", record.get("exit_code")))
                    if termination.get("attempted") is True:
                        if (termination.get("succeeded") is not True or termination.get("error") != 0 or
                                termination.get("reason") != "output_overflow"):
                            problems.append(issue("OUTPUT_LIMIT_TERMINATION_INCOMPLETE", termination))
                    elif termination.get("attempted") is not False or record.get("exit_code") != 0:
                        problems.append(issue("OUTPUT_LIMIT_RETIREMENT_UNEXPLAINED", "without owned termination the producer must have exited normally"))
                else:
                    if record.get("exit_code") != CONTROL_EXCEPTION:
                        problems.append(issue("EXCEPTION_CONTROL_EXIT_MISMATCH", record.get("exit_code")))
                    events = receipt.get("events", [])
                    exceptions = [event for event in events if isinstance(event, dict) and
                                  event.get("type") == "exception" and event.get("code") == CONTROL_EXCEPTION] if isinstance(events, list) else []
                    if (len(exceptions) != 2 or {event.get("first_chance") for event in exceptions} != {0, 1} or
                            any(event.get("continuation_status") != 0x80010001 or event.get("continued") is not True
                                for event in exceptions)):
                        problems.append(issue("EXCEPTION_CONTROL_SWALLOWED_OR_UNOBSERVED", "both first and second chance events must be passed as DBG_EXCEPTION_NOT_HANDLED"))
                independent_pass = not problems
                if record.get("oracle_passed") is not independent_pass:
                    problems.append(issue("DRIVER_CONTROL_ORACLE_DISAGREES", {
                        "driver": record.get("oracle_passed"), "independent": independent_pass}))
            rows.append({"platform": platform, "id": cid, "synthetic_control": True,
                         "accepted": not problems, "issues": problems})
    return {"schema": SCHEMA, "accepted": not global_issues and all(row["accepted"] for row in rows),
            "scope": "deadline, retained-output bound, and pass-through of a non-debugger unhandled exception",
            "included_in_target_case_counts": False, "issues": global_issues, "cases": rows}


def sensor_coverage(reports):
    coverage = {}
    counter_fields = ("read_operations", "write_operations", "other_operations", "read_bytes", "write_bytes", "other_bytes")
    for platform, report in reports.items():
        rows, counts = [], {}
        for record in sequence(report.get("cases")) + sequence(report.get("actuators")):
            if not isinstance(record, dict):
                continue
            observer = mapping(record.get("observer"))
            receipt = mapping(observer.get("receipt"))
            io = mapping(mapping(receipt.get("metrics")).get("io"))
            state = "api_unavailable"
            if io.get("available") is True and io.get("error") == 0:
                values = [io.get(field) for field in counter_fields]
                numeric = all(isinstance(value, str) and value.isdecimal() for value in values)
                if not numeric:
                    state = "invalid_counter_receipt"
                else:
                    state = "reported_not_independently_attributed"
                    file_effect = isinstance(record.get("before"), dict) and isinstance(record.get("after"), dict) and record["before"] != record["after"]
                    stream_effect = bool(record.get("stdout_hex")) or bool(record.get("stderr_hex"))
                    if all(int(value) == 0 for value in values) and (file_effect or stream_effect):
                        state = "unqualified_zero_counters_despite_observed_effects"
            counts[state] = counts.get(state, 0) + 1
            rows.append({"id": record.get("id"), "subject": record.get("subject"), "mode": record.get("mode"),
                         "process_io": state, "raw_io": io,
                         "adapter_process_io": mapping(observer.get("sensor_quality")).get("process_io")})
        coverage[platform] = {"counts": counts, "cases": rows}
    return {"full_stack_observability_qualified": False,
            "qualified_scope": "bounded process control, mapped-image/debug events, captured streams and independent persistent file effects, subject to individual checks",
            "process_io_limit": "API success or nonzero totals do not prove per-path attribution; all-zero totals despite observed effects remain semantically unqualified.",
            "platforms": coverage}


def write_json(path, value):
    path.write_text(json.dumps(value, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--windows", type=Path, required=True)
    parser.add_argument("--wine", type=Path, required=True)
    parser.add_argument("--outputdir", type=Path, required=True)
    args = parser.parse_args(argv)
    args.outputdir.mkdir(parents=True, exist_ok=True)
    manifest_path = Path(__file__).with_name("validation_cases.json")
    try:
        manifest_bytes = manifest_path.read_bytes()
        if sha(manifest_bytes) != FROZEN_CASE_SHA256:
            raise ValueError("Frozen validation manifest digest mismatch; do not silently replace the corpus")
        manifest = json.loads(manifest_bytes)
        if manifest.get("schema") != CASE_SCHEMA:
            raise ValueError("Unexpected frozen case schema")
        if manifest.get("target", {}).get("archive_sha256") != ARCHIVE_SHA256:
            raise ValueError("Unexpected reference archive pin")
        cases = manifest["cases"]
        reports, indexes, report_problems = {}, {}, {}
        for platform, path in (("windows", args.windows), ("wine", args.wine)):
            reports[platform], indexes[platform], report_problems[platform] = load_report(path, platform, cases)
    except (OSError, ValueError, KeyError, TypeError) as exc:
        result = {"schema": SCHEMA, "accepted": False, "classification": "HARNESS_FAILURE",
                  "error": str(exc)}
        write_json(args.outputdir / "validation-report.json", result)
        print(json.dumps(result))
        return 2
    cross_digest_issues = []
    for key in ("target_sha256", "candidate_sha256"):
        if reports["windows"].get(key) != reports["wine"].get(key):
            cross_digest_issues.append(issue("CROSS_PLATFORM_DIGEST_MISMATCH", key))
    for platform in report_problems:
        report_problems[platform] += cross_digest_issues
    specs = [
        ("native-reconstruction", "windows", "reference", "windows", "candidate"),
        ("wine-reconstruction", "wine", "reference", "wine", "candidate"),
        ("reference-cross-platform", "windows", "reference", "wine", "reference"),
        ("candidate-cross-platform", "windows", "candidate", "wine", "candidate"),
    ]
    comparisons = [compare_pair(*spec, cases, reports, indexes, report_problems) for spec in specs]
    controls = negative_controls(cases, reports, indexes)
    actuators = actuator_checks(reports)
    observer_controls = observer_control_checks(reports)
    coverage = sensor_coverage(reports)
    accepted = (all(c["accepted"] for c in comparisons) and controls["accepted"] and
                actuators["accepted"] and observer_controls["accepted"])
    result = {
        "schema": SCHEMA, "accepted": accepted,
        "classification": "PASS_BOUNDED" if accepted else "NOT_QUALIFIED",
        "reconstruction_conformance": all(c["accepted"] for c in comparisons[:2]),
        "cross_platform_identity": all(c["accepted"] for c in comparisons[2:]),
        "instrumentation_controls_qualified": controls["accepted"] and actuators["accepted"] and observer_controls["accepted"],
        "summary_field_scope": {
            "reconstruction_conformance": "Both strict within-platform reference-versus-reconstruction comparisons accepted.",
            "cross_platform_identity": "Both strict cross-platform comparisons accepted, including raw/narrowly normalized diagnostics.",
            "instrumentation_controls_qualified": "Runtime actuators, synthetic observer controls and comparator negative controls all accepted; full-stack coverage is not implied.",
            "accepted": "Unchanged strict whole-matrix and instrumentation-control acceptance.",
        },
        "case_manifest_sha256": sha(manifest_bytes), "frozen_at_utc": manifest["frozen_at_utc"],
        "case_count": len(cases), "primary_case_count": sum(not c["challenge"] for c in cases),
        "challenge_case_count": sum(c["challenge"] for c in cases),
        "target_archive_sha256": ARCHIVE_SHA256,
        "target_sha256": {p: r.get("target_sha256") for p, r in reports.items()},
        "candidate_sha256": {p: r.get("candidate_sha256") for p, r in reports.items()},
        "report_input_sha256": {"windows": sha(args.windows.read_bytes()), "wine": sha(args.wine.read_bytes())},
        "normalization_policy": {
            "version": 1, "program_names": [n.decode("ascii") for n in DIAGNOSTIC_PROGRAM_NAMES],
            "rule": "Only a declared diagnostic program name at line start immediately followed by ':' becomes <PROGRAM>.",
            "temporary_names": "none; any temporary-name difference remains visible",
            "raw_stderr_retained": True,
        },
        "effect_scope": "Persistent path/content changes, not proof that every actual write operation was observed.",
        "comparisons": comparisons, "negative_controls": controls, "actuators": actuators,
        "observer_controls": observer_controls, "sensor_coverage": coverage,
    }
    write_json(args.outputdir / "validation-report.json", result)
    write_json(args.outputdir / "comparison-matrix.json", {"schema": SCHEMA, "comparisons": comparisons})
    for comparison in comparisons[2:]:
        write_json(args.outputdir / (comparison["name"] + ".json"), comparison)
    write_json(args.outputdir / "negative-controls.json", controls)
    write_json(args.outputdir / "actuator-validation.json", actuators)
    write_json(args.outputdir / "observer-control-validation.json", observer_controls)
    write_json(args.outputdir / "sensor-coverage.json", coverage)
    lines = ["# Windows/Wine independent validation", "",
             f"Whole-corpus qualification: **{result['classification']}**.", "",
             f"Reconstruction conformance: **{result['reconstruction_conformance']}**. "
             f"Cross-platform identity: **{result['cross_platform_identity']}**. "
             f"Instrumentation controls qualified: **{result['instrumentation_controls_qualified']}**.", "",
             f"Frozen corpus: {len(cases)} cases; {result['primary_case_count']} primary and "
             f"{result['challenge_case_count']} explicit challenges. Challenges remain part of whole-corpus acceptance.", "",
             "| Comparison | Behavior matches | Fully accepted | Primary contract | Challenges |",
             "| --- | ---: | ---: | --- | --- |"]
    for comparison in comparisons:
        lines.append(f"| {comparison['name']} | {comparison['behavior_matches']}/{len(cases)} | "
                     f"{comparison['accepted_cases']}/{len(cases)} | "
                     f"{comparison['primary_contract_accepted']} | {comparison['challenge_contract_accepted']} |")
    lines += ["", f"Comparator negative controls passed: **{controls['accepted']}**.", "",
              f"Independent runtime actuator checks passed: **{actuators['accepted']}**.", "",
              f"Independent synthetic observer controls passed: **{observer_controls['accepted']}**. "
              "These controls are excluded from target-case counts.", "",
              "Full-stack observability is not established by this bounded exercise. "
              "The separate sensor-coverage report retains raw process I/O values and flags zero totals despite witnessed effects.", "",
              "Byte conformance and complete observation are separate. Missing debugger capability, "
              "missing cases, digest mismatches, timeouts and incomplete capture do not pass full qualification.", "",
              "The JSON reports retain per-case classifications, raw diagnostics, byte mismatch locations, "
              "persistent effects and evidence gaps. No upstream implementation source is used by this comparator.", ""]
    (args.outputdir / "validation-summary.md").write_text("\n".join(lines), encoding="utf-8")
    print(json.dumps({"accepted": accepted, "classification": result["classification"],
                      "case_count": len(cases), "negative_controls_passed": controls["accepted"],
                      "output": str(args.outputdir / "validation-report.json")}))
    return 0 if accepted else 1


if __name__ == "__main__":
    sys.exit(main())
