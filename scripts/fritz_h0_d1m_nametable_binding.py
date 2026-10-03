#!/usr/bin/env python3
"""H0-D1m: recover nametable row bindings behind linux_fs_start selection.

D1l reduced the selector arms to:
  selector 0 -> nametable[i].runtime_name_0
  selector 1 -> nametable[i].runtime_name_1

D1m examines only the nametable declaration/initializer and mechanically
recognized uses of nametable[i]. It persists safe identifiers and restrictive
destination-like strings, never source snippets, arbitrary literals, offsets,
or writable HIL instructions.
"""
from __future__ import annotations

import argparse
import importlib.util
import json
import pathlib
import re

_D1L_PATH = pathlib.Path(__file__).with_name("fritz_h0_d1l_selector_arm_skeleton.py")
_SPEC = importlib.util.spec_from_file_location("fritz_h0_d1l_selector_arm_skeleton", _D1L_PATH)
if _SPEC is None or _SPEC.loader is None:
    raise RuntimeError("unable to load D1l")
d1l = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(d1l)
d1k = d1l.d1k
d1h = d1l.d1h

SCHEMA_VERSION = 1
EXPERIMENT = "fritz-h0-d1m-nametable-binding/v1"
FILES = d1h.FILES
TABLE = "nametable"
INDEX = "i"
RUNTIME_FIELDS = ("runtime_name_0", "runtime_name_1")
SAFE_DEST_RE = d1h.SAFE_DEST_RE
_IDENT = r"[A-Za-z_][A-Za-z0-9_]*"


def split_top_level(value: str) -> list[str]:
    out: list[str] = []
    start = 0
    quote = None
    escape = False
    depths = {"(": 0, "[": 0, "{": 0}
    pairs = {")": "(", "]": "[", "}": "{"}
    for i, ch in enumerate(value):
        if quote:
            if escape:
                escape = False
            elif ch == "\\":
                escape = True
            elif ch == quote:
                quote = None
            continue
        if ch in {'"', "'"}:
            quote = ch
            continue
        if ch in depths:
            depths[ch] += 1
            continue
        if ch in pairs:
            key = pairs[ch]
            depths[key] = max(0, depths[key] - 1)
            continue
        if ch == "," and all(v == 0 for v in depths.values()):
            out.append(value[start:i].strip())
            start = i + 1
    tail = value[start:].strip()
    if tail:
        out.append(tail)
    return out


def struct_fields(masked_block: str) -> list[str]:
    fields = []
    for stmt in masked_block.split(";"):
        tokens = re.findall(rf"\b{_IDENT}\b", stmt)
        if not tokens:
            continue
        candidate = tokens[-1]
        if candidate in {
            "const","volatile","struct","union","enum","char","short","int",
            "long","unsigned","signed","void",
        }:
            continue
        fields.append(candidate)
    return fields


def struct_definitions(text: str) -> list[dict]:
    masked = d1h.mask_comments_strings(text)
    rx = re.compile(rf"\bstruct(?:\s+(?P<name>{_IDENT}))?\s*\{{")
    out = []
    for m in rx.finditer(masked):
        open_idx = masked.find("{", m.start(), m.end())
        close_idx = d1h.match_brace(text, open_idx)
        if close_idx is None:
            continue
        out.append({
            "name": m.group("name"),
            "start": m.start(),
            "open": open_idx,
            "close": close_idx,
            "fields": struct_fields(masked[open_idx + 1:close_idx]),
        })
    return out


def locate_table_initializer(text: str) -> dict | None:
    masked = d1h.mask_comments_strings(text)
    rx = re.compile(rf"\b{TABLE}\s*(?:\[[^\]]*\])?\s*=\s*\{{")
    m = rx.search(masked)
    if not m:
        return None
    open_idx = masked.find("{", m.start(), m.end())
    close_idx = d1h.match_brace(text, open_idx)
    if close_idx is None:
        return None
    return {
        "nameStart": m.start(),
        "open": open_idx,
        "close": close_idx,
    }


def infer_table_fields(text: str, table: dict) -> dict:
    masked = d1h.mask_comments_strings(text)
    defs = struct_definitions(text)

    prefix = masked[max(0, table["nameStart"] - 240):table["nameStart"]]
    named = None
    m = re.search(rf"\bstruct\s+(?P<name>{_IDENT})\s+(?:const\s+)?$", prefix)
    if not m:
        m = re.search(rf"\bstruct\s+(?P<name>{_IDENT})[^;{{}}]*$", prefix)
    if m:
        named = m.group("name")
        candidates = [d for d in defs if d["name"] == named]
        if candidates:
            d = candidates[-1]
            return {
                "typeClass": "named_struct",
                "typeName": named,
                "fieldNames": d["fields"],
            }

    # Anonymous struct directly declaring nametable.
    candidates = []
    for d in defs:
        if d["name"] is not None or d["close"] >= table["nameStart"]:
            continue
        tail = masked[d["close"] + 1:table["nameStart"]]
        if ";" in tail:
            continue
        if re.search(r"\bnametable\b", tail):
            candidates.append(d)
    if candidates:
        d = candidates[-1]
        return {
            "typeClass": "anonymous_struct",
            "typeName": None,
            "fieldNames": d["fields"],
        }

    # Fallback: uniquely identify a struct containing both runtime fields.
    candidates = [
        d for d in defs
        if all(field in d["fields"] for field in RUNTIME_FIELDS)
    ]
    if len(candidates) == 1:
        d = candidates[0]
        return {
            "typeClass": "unique_runtime_field_struct",
            "typeName": d["name"],
            "fieldNames": d["fields"],
        }

    return {
        "typeClass": "unresolved",
        "typeName": named,
        "fieldNames": [],
    }


def row_spans(text: str, table: dict) -> list[tuple[int, int]]:
    masked = d1h.mask_comments_strings(text)
    spans = []
    depth = 0
    start = None
    for i in range(table["open"] + 1, table["close"]):
        ch = masked[i]
        if ch == "{":
            if depth == 0:
                start = i
            depth += 1
        elif ch == "}":
            depth -= 1
            if depth == 0 and start is not None:
                spans.append((start, i))
                start = None
    return spans


def direct_safe_string(expr: str) -> str | None:
    return d1k.direct_safe_string(expr)


def parse_row(row_text: str, fields: list[str]) -> dict:
    inner = row_text.strip()
    if inner.startswith("{") and inner.endswith("}"):
        inner = inner[1:-1]

    designated = {}
    for field in fields:
        rx = re.compile(
            rf"\.\s*{re.escape(field)}\s*=\s*([\"'][^\"']+[\"'])"
        )
        m = rx.search(inner)
        if m:
            value = direct_safe_string(m.group(1))
            if value is not None:
                designated[field] = value

    positional = {}
    items = split_top_level(inner)
    if fields and len(items) >= len(fields):
        for field, item in zip(fields, items):
            value = direct_safe_string(item)
            if value is not None:
                positional[field] = value

    values = {**positional, **designated}
    runtime = {
        field: values.get(field)
        for field in RUNTIME_FIELDS
    }
    safe_named_fields = {
        field: value
        for field, value in values.items()
        if (
            value is not None
            and field not in RUNTIME_FIELDS
            and any(token in field.lower() for token in ("name", "mtd", "part", "logical"))
        )
    }
    return {
        "runtimeNames": runtime,
        "safeNamedFields": dict(sorted(safe_named_fields.items())),
        "recognizedSafeFieldCount": len(values),
        "initializerMode": (
            "designated" if designated
            else "positional" if positional
            else "unresolved"
        ),
    }


def index_field_references(text: str) -> dict:
    masked = d1h.mask_comments_strings(text)
    rx = re.compile(
        rf"\b{TABLE}\s*\[\s*{INDEX}\s*\]\s*\.\s*(?P<field>{_IDENT})"
    )
    counts = {}
    comparison_counts = {}
    for m in rx.finditer(masked):
        field = m.group("field")
        counts[field] = counts.get(field, 0) + 1
        lo = max(0, m.start() - 180)
        hi = min(len(masked), m.end() + 180)
        window = masked[lo:hi]
        if re.search(r"\b(?:strcmp|strncmp|strcasecmp)\s*\(", window):
            comparison_counts[field] = comparison_counts.get(field, 0) + 1
    candidates = sorted(
        field for field, count in comparison_counts.items()
        if count > 0 and field not in RUNTIME_FIELDS
    )
    return {
        "fieldReferenceCounts": dict(sorted(counts.items())),
        "stringComparisonFieldCounts": dict(sorted(comparison_counts.items())),
        "uniqueStringComparisonSelectionField": candidates[0] if len(candidates) == 1 else None,
    }


def recover_table(text: str) -> dict:
    table = locate_table_initializer(text)
    if table is None:
        return {
            "tableFound": False,
            "type": {"typeClass": "unresolved", "typeName": None, "fieldNames": []},
            "rowCount": 0,
            "rows": [],
            "indexBinding": index_field_references(text),
        }
    type_info = infer_table_fields(text, table)
    fields = type_info["fieldNames"]
    rows = [
        parse_row(text[start:end + 1], fields)
        for start, end in row_spans(text, table)
    ]
    return {
        "tableFound": True,
        "type": type_info,
        "rowCount": len(rows),
        "rows": rows,
        "indexBinding": index_field_references(text),
    }


def row_bindings(recovery: dict) -> list[dict]:
    selection = recovery["indexBinding"].get("uniqueStringComparisonSelectionField")
    if not selection:
        return []
    out = []
    for row in recovery["rows"]:
        key = row["safeNamedFields"].get(selection)
        r0 = row["runtimeNames"].get("runtime_name_0")
        r1 = row["runtimeNames"].get("runtime_name_1")
        if key is None or r0 is None or r1 is None:
            continue
        out.append({
            "rowKeyField": selection,
            "rowKey": key,
            "runtimeName0": r0,
            "runtimeName1": r1,
        })
    return out


def crosscheck(destinations: list[str], selected: dict[str, str]) -> list[dict]:
    out = []
    for dest in sorted(set(destinations)):
        matches = []
        for path, text in sorted(selected.items()):
            if path.endswith("avm_mtd.c"):
                continue
            count = len(re.findall(
                rf"(?<![A-Za-z0-9_.+-]){re.escape(dest)}(?![A-Za-z0-9_.+-])",
                text,
            ))
            if count:
                matches.append({"file": path, "count": count})
        out.append({
            "destination": dest,
            "independentMatches": matches,
            "independentlyObserved": bool(matches),
        })
    return out


def classify(recovery: dict, bindings: list[dict], checks: list[dict], missing: list[str]) -> str:
    if missing:
        return "H0_D1M_SOURCE_MISSING"
    if bindings:
        destinations = {
            value
            for row in bindings
            for value in (row["runtimeName0"], row["runtimeName1"])
        }
        checked = {x["destination"] for x in checks}
        if destinations and checked == destinations and all(
            x["independentlyObserved"] for x in checks
        ):
            return "H0_D1M_NAMETABLE_BINDINGS_CROSSCHECKED"
        return "H0_D1M_NAMETABLE_BINDINGS_RECOVERED"
    if recovery.get("tableFound") and recovery.get("rowCount", 0) > 0:
        return "H0_D1M_NAMETABLE_ROWS_PARTIAL"
    if recovery.get("tableFound"):
        return "H0_D1M_NAMETABLE_INITIALIZER_PARTIAL"
    return "H0_D1M_NAMETABLE_NOT_FOUND"


def run_probe(args):
    work = pathlib.Path(args.work_dir).resolve()
    work.mkdir(parents=True, exist_ok=True)
    archive = work / "source-files.tar.gz"
    exact = d1h.download_exact(args.osp_url, archive, args.expected_size, args.expected_sha256)
    selected = d1h.extract_selected(archive)
    missing = sorted(set(FILES) - set(selected))
    avm_path = "sources/kernel/linux/drivers/mtd/avm/avm_mtd.c"
    recovery = recover_table(selected.get(avm_path, ""))
    bindings = row_bindings(recovery)
    destinations = [
        value for row in bindings for value in (row["runtimeName0"], row["runtimeName1"])
    ]
    checks = crosscheck(destinations, selected)

    return {
        "schemaVersion": SCHEMA_VERSION,
        "experiment": EXPERIMENT,
        "classification": classify(recovery, bindings, checks, missing),
        "oracleSatisfied": not missing,
        "sourceArtifact": {
            "expectedBytes": args.expected_size,
            "expectedSha256": args.expected_sha256.lower(),
            "observedBytes": exact["bytes"],
            "observedSha256": exact["sha256"],
        },
        "missingFiles": missing,
        "nametable": recovery,
        "rowBindings": bindings,
        "destinationCrosscheck": checks,
        "derived": {
            "rowCount": recovery.get("rowCount", 0),
            "rowBindingCount": len(bindings),
            "selectionFieldRecovered": bool(
                recovery.get("indexBinding", {}).get("uniqueStringComparisonSelectionField")
            ),
            "runtimeDestinationCount": len(set(destinations)),
            "independentlyObservedDestinationCount": sum(
                1 for x in checks if x["independentlyObserved"]
            ),
        },
        "interpretationBoundary": {
            "selectorDomainAcceptedFromD1h": [0, 1],
            "selectorZeroUsesRuntimeName0": True,
            "selectorOneUsesRuntimeName1": True,
            "onlySafeNamedTableStringsPublished": True,
            "rowSelectionRequiresUniqueStringComparisonField": True,
            "tableBindingIsNotBootabilityProof": True,
            "exactFlashOffsetsAccepted": False,
            "inactiveSlotSafetyAccepted": False,
            "rollbackSafetyAccepted": False,
            "modifiedHilAuthorized": False,
        },
        "safety": {
            "rawOspArchivePublished": False,
            "sourcePayloadPublished": False,
            "sourceSnippetsPublished": False,
            "arbitraryStringLiteralsPublished": False,
            "numericFlashOffsetsPublished": False,
            "physicalRouterContact": False,
            "flashWriteAuthorized": False,
            "bootEnvironmentMutationAuthorized": False,
        },
    }


def parse_args(argv=None):
    p = argparse.ArgumentParser()
    p.add_argument("--osp-url", required=True)
    p.add_argument("--expected-size", type=int, required=True)
    p.add_argument("--expected-sha256", required=True)
    p.add_argument("--work-dir", required=True)
    p.add_argument("--receipt", required=True)
    return p.parse_args(argv)


def main(argv=None):
    args = parse_args(argv)
    receipt = pathlib.Path(args.receipt)
    receipt.parent.mkdir(parents=True, exist_ok=True)
    try:
        data = run_probe(args)
        rc = 0 if data["oracleSatisfied"] else 2
    except Exception as exc:
        data = {
            "schemaVersion": SCHEMA_VERSION,
            "experiment": EXPERIMENT,
            "classification": "HARNESS_FAILURE",
            "oracleSatisfied": False,
            "error": {"type": type(exc).__name__, "message": str(exc)[:1000]},
            "safety": {
                "rawOspArchivePublished": False,
                "sourcePayloadPublished": False,
                "sourceSnippetsPublished": False,
                "arbitraryStringLiteralsPublished": False,
                "numericFlashOffsetsPublished": False,
                "physicalRouterContact": False,
                "flashWriteAuthorized": False,
                "bootEnvironmentMutationAuthorized": False,
            },
        }
        rc = 3
    receipt.write_text(json.dumps(data, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps({"classification": data["classification"], "oracleSatisfied": data["oracleSatisfied"]}, sort_keys=True))
    return rc


if __name__ == "__main__":
    raise SystemExit(main())
