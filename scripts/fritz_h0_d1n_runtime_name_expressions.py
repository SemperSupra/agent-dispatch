#!/usr/bin/env python3
"""H0-D1n: reduce unresolved nametable runtime-name initializer expressions.

Authority: SemperSupra/fritzbox-automation-private#75.

D1m recovered the nametable field set and row-selection relation but left
runtime_name_0/runtime_name_1 unresolved. This reducer examines only those two
field initializer expressions and emits sanitized identifier/shape evidence plus
restrictive destination-like names when mechanically bound. It does not publish
source snippets, arbitrary literals, offsets, or mutation instructions.
"""
from __future__ import annotations

import argparse
import importlib.util
import json
import pathlib
import re

_D1M_PATH = pathlib.Path(__file__).with_name("fritz_h0_d1m_nametable_binding.py")
_SPEC = importlib.util.spec_from_file_location("fritz_h0_d1m_nametable_binding", _D1M_PATH)
if _SPEC is None or _SPEC.loader is None:
    raise RuntimeError("unable to load D1m")
d1m = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(d1m)
d1h = d1m.d1h

SCHEMA_VERSION = 1
EXPERIMENT = "fritz-h0-d1n-runtime-name-expressions/v1"
FILES = d1m.FILES
AVM_PATH = "sources/kernel/linux/drivers/mtd/avm/avm_mtd.c"
FIELDS = ("runtime_name_0", "runtime_name_1")
_IDENT = r"[A-Za-z_][A-Za-z0-9_]*"
_C_KEYWORDS = {
    "auto","break","case","char","const","continue","default","do","double",
    "else","enum","extern","float","for","goto","if","inline","int","long",
    "register","restrict","return","short","signed","sizeof","static","struct",
    "switch","typedef","union","unsigned","void","volatile","while",
}


def _strip_outer_braces(row_text: str) -> str:
    value = row_text.strip()
    if value.startswith("{") and value.endswith("}"):
        return value[1:-1]
    return value


def _designated_item(item: str) -> tuple[str, str] | None:
    m = re.match(rf"^\s*\.\s*(?P<field>{_IDENT})\s*=\s*(?P<expr>.+?)\s*$", item, re.S)
    if not m:
        return None
    return m.group("field"), m.group("expr")


def runtime_field_expressions(text: str) -> dict:
    table = d1m.locate_table_initializer(text)
    if table is None:
        return {
            "tableFound": False,
            "fieldNames": [],
            "rowCount": 0,
            "rows": [],
        }

    type_info = d1m.infer_table_fields(text, table)
    fields = type_info.get("fieldNames", [])
    rows = []
    for start, end in d1m.row_spans(text, table):
        inner = _strip_outer_braces(text[start:end + 1])
        items = d1m.split_top_level(inner)
        designated = {}
        positional = {}
        for item in items:
            parsed = _designated_item(item)
            if parsed:
                designated[parsed[0]] = parsed[1]
        if not designated and fields:
            for field, expr in zip(fields, items):
                positional[field] = expr

        chosen = designated if designated else positional
        rows.append({
            "mode": "designated" if designated else "positional" if positional else "unresolved",
            "topLevelItemCount": len(items),
            "topLevelItemSkeletons": [row_item_skeleton(item) for item in items],
            "expressions": {
                field: chosen.get(field)
                for field in FIELDS
            },
        })

    return {
        "tableFound": True,
        "fieldNames": fields,
        "rowCount": len(rows),
        "rows": rows,
    }


def _safe_literals(expr: str) -> list[str]:
    out = []
    for m in re.finditer(r'(["\'])(?P<value>[^"\']+)\1', expr):
        value = m.group("value")
        if d1h.SAFE_DEST_RE.fullmatch(value):
            out.append(value)
    return sorted(set(out))


def _operator_classes(masked: str) -> list[str]:
    classes = []
    tests = [
        ("call", r"\b[A-Za-z_][A-Za-z0-9_]*\s*\("),
        ("array_index", r"\[[^\]]*\]"),
        ("member", r"(?:->|\.)\s*[A-Za-z_]"),
        ("ternary", r"\?.*:"),
        ("address_of", r"(^|[^&])&\s*[A-Za-z_(]"),
        ("dereference", r"(^|[^*/])\*\s*[A-Za-z_(]"),
        ("cast", r"\(\s*(?:const\s+)?(?:char|int|long|unsigned|signed|struct\s+[A-Za-z_][A-Za-z0-9_]*)[^)]*\)"),
        ("arithmetic", r"[+\-*/%]"),
        ("logical", r"(?:&&|\|\||!)"),
        ("comparison", r"(?:==|!=|<=|>=|<|>)"),
        ("bitwise", r"(?:<<|>>|\^|\||&)"),
    ]
    for name, pattern in tests:
        if re.search(pattern, masked):
            classes.append(name)
    return classes


def row_item_skeleton(expr: str) -> dict:
    """Sanitize one top-level row item without exposing literals/snippets."""
    masked = d1h.mask_comments_strings(expr)
    identifiers = []
    seen = set()
    for m in re.finditer(rf"\b(?P<name>{_IDENT})\b", masked):
        name = m.group("name")
        if name in _C_KEYWORDS or name in seen:
            continue
        seen.add(name)
        after = masked[m.end():m.end() + 8]
        roles = []
        if re.match(r"\s*\(", after):
            roles.append("function_like")
        if re.match(r"\s*\[", after):
            roles.append("array_base")
        if name.upper() == name and "_" in name:
            roles.append("macro_like")
        if not roles:
            roles.append("plain_identifier")
        identifiers.append({"name": name, "roles": roles})
    return {
        "identifiers": identifiers,
        "operatorClasses": _operator_classes(masked),
        "safeLiteralCandidateCount": len(_safe_literals(expr)),
    }


def expression_skeleton(expr: str | None) -> dict:
    if expr is None:
        return {
            "present": False,
            "identifiers": [],
            "operatorClasses": [],
            "safeLiteralCandidates": [],
            "directSafeDestination": None,
        }
    masked = d1h.mask_comments_strings(expr)
    identifiers = []
    seen = set()
    for m in re.finditer(rf"\b(?P<name>{_IDENT})\b", masked):
        name = m.group("name")
        if name in _C_KEYWORDS or name in seen:
            continue
        seen.add(name)
        before = masked[max(0, m.start() - 4):m.start()]
        after = masked[m.end():m.end() + 8]
        roles = []
        if re.match(r"\s*\(", after):
            roles.append("function_like")
        if re.match(r"\s*\[", after):
            roles.append("array_base")
        if re.search(r"(?:->|\.)\s*$", before):
            roles.append("member")
        if name.upper() == name and "_" in name:
            roles.append("macro_like")
        if not roles:
            roles.append("plain_identifier")
        identifiers.append({"name": name, "roles": roles})

    return {
        "present": True,
        "identifiers": identifiers,
        "operatorClasses": _operator_classes(masked),
        "safeLiteralCandidates": _safe_literals(expr),
        "directSafeDestination": d1m.direct_safe_string(expr),
    }


def _macro_rhs(text: str, name: str) -> list[str]:
    rx = re.compile(
        rf"^[ \t]*#[ \t]*define[ \t]+{re.escape(name)}\b(?!\s*\()(?P<rhs>[^\r\n]+)",
        re.M,
    )
    return [m.group("rhs").strip() for m in rx.finditer(text)]


def _assignment_rhs(text: str, name: str) -> list[str]:
    masked = d1h.mask_comments_strings(text)
    out = []
    rx = re.compile(rf"\b{re.escape(name)}\b\s*=\s*")
    for m in rx.finditer(masked):
        start = m.end()
        depth = {"(": 0, "[": 0, "{": 0}
        quote = None
        escape = False
        for i in range(start, len(text)):
            ch = text[i]
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
            if ch in depth:
                depth[ch] += 1
                continue
            if ch == ")" and depth["("]:
                depth["("] -= 1
                continue
            if ch == "]" and depth["["]:
                depth["["] -= 1
                continue
            if ch == "}" and depth["{"]:
                depth["{"] -= 1
                continue
            if ch in ",;" and all(v == 0 for v in depth.values()):
                out.append(text[start:i].strip())
                break
    return out


def _single_identifier(expr: str) -> str | None:
    value = expr.strip()
    return value if re.fullmatch(_IDENT, value) else None


def _resolve_expr(expr: str | None, text: str, depth: int = 0, seen=None) -> dict:
    if expr is None:
        return {"resolvedDestination": None, "resolution": "missing"}
    if depth > 4:
        return {"resolvedDestination": None, "resolution": "depth_limit"}
    seen = set() if seen is None else set(seen)

    direct = d1m.direct_safe_string(expr)
    if direct is not None:
        return {"resolvedDestination": direct, "resolution": "direct_string"}

    literals = _safe_literals(expr)
    if len(literals) == 1:
        return {"resolvedDestination": literals[0], "resolution": "unique_safe_literal_in_expression"}

    ident = _single_identifier(expr)
    if ident is None or ident in seen:
        return {"resolvedDestination": None, "resolution": "expression_partial"}

    seen.add(ident)
    defs = _macro_rhs(text, ident)
    assigns = _assignment_rhs(text, ident)
    candidates = defs + assigns
    if len(candidates) != 1:
        return {
            "resolvedDestination": None,
            "resolution": "identifier_definition_ambiguous" if candidates else "identifier_definition_missing",
            "identifier": ident,
            "definitionCount": len(candidates),
        }
    nested = _resolve_expr(candidates[0], text, depth + 1, seen)
    return {
        **nested,
        "identifier": ident,
        "definitionCount": 1,
        "resolutionChainDepth": depth + 1,
    }


def reduce_rows(text: str) -> dict:
    located = runtime_field_expressions(text)
    out_rows = []
    for row in located["rows"]:
        fields = {}
        for field in FIELDS:
            expr = row["expressions"].get(field)
            fields[field] = {
                "skeleton": expression_skeleton(expr),
                "resolution": _resolve_expr(expr, text),
            }
        out_rows.append({
            "mode": row["mode"],
            "topLevelItemCount": row.get("topLevelItemCount", 0),
            "topLevelItemSkeletons": row.get("topLevelItemSkeletons", []),
            "fields": fields,
        })
    return {
        "tableFound": located["tableFound"],
        "fieldNames": located["fieldNames"],
        "rowCount": located["rowCount"],
        "rows": out_rows,
    }


def resolved_destinations(reduced: dict) -> list[dict]:
    out = []
    for idx, row in enumerate(reduced["rows"]):
        for field in FIELDS:
            value = row["fields"][field]["resolution"].get("resolvedDestination")
            if value is not None:
                out.append({"rowIndex": idx, "field": field, "destination": value})
    return out


def crosscheck(destinations: list[dict], selected: dict[str, str]) -> list[dict]:
    out = []
    for item in destinations:
        dest = item["destination"]
        matches = []
        for path, text in sorted(selected.items()):
            if path == AVM_PATH:
                continue
            count = len(re.findall(
                rf"(?<![A-Za-z0-9_.+-]){re.escape(dest)}(?![A-Za-z0-9_.+-])",
                text,
            ))
            if count:
                matches.append({"file": path, "count": count})
        out.append({
            **item,
            "independentMatches": matches,
            "independentlyObserved": bool(matches),
        })
    return out


def classify(reduced: dict, destinations: list[dict], checks: list[dict], missing: list[str]) -> str:
    if missing:
        return "H0_D1N_SOURCE_MISSING"
    if not reduced.get("tableFound"):
        return "H0_D1N_NAMETABLE_NOT_FOUND"
    expected = reduced.get("rowCount", 0) * len(FIELDS)
    if expected and len(destinations) == expected:
        if checks and all(x["independentlyObserved"] for x in checks):
            return "H0_D1N_RUNTIME_NAMES_CROSSCHECKED"
        return "H0_D1N_RUNTIME_NAMES_RECOVERED"
    if any(
        row["fields"][field]["skeleton"].get("present")
        for row in reduced.get("rows", [])
        for field in FIELDS
    ):
        return "H0_D1N_RUNTIME_NAME_EXPRESSIONS_PARTIAL"
    return "H0_D1N_RUNTIME_NAME_EXPRESSIONS_UNRESOLVED"


def run_probe(args):
    work = pathlib.Path(args.work_dir).resolve()
    work.mkdir(parents=True, exist_ok=True)
    archive = work / "source-files.tar.gz"
    exact = d1h.download_exact(args.osp_url, archive, args.expected_size, args.expected_sha256)
    selected = d1h.extract_selected(archive)
    missing = sorted(set(FILES) - set(selected))
    reduced = reduce_rows(selected.get(AVM_PATH, ""))
    destinations = resolved_destinations(reduced)
    checks = crosscheck(destinations, selected)

    return {
        "schemaVersion": SCHEMA_VERSION,
        "experiment": EXPERIMENT,
        "classification": classify(reduced, destinations, checks, missing),
        "oracleSatisfied": not missing,
        "sourceArtifact": {
            "expectedBytes": args.expected_size,
            "expectedSha256": args.expected_sha256.lower(),
            "observedBytes": exact["bytes"],
            "observedSha256": exact["sha256"],
        },
        "missingFiles": missing,
        "runtimeNameExpressions": reduced,
        "resolvedDestinations": destinations,
        "destinationCrosscheck": checks,
        "derived": {
            "rowCount": reduced.get("rowCount", 0),
            "resolvedDestinationCount": len(destinations),
            "independentlyObservedDestinationCount": sum(
                1 for x in checks if x["independentlyObserved"]
            ),
        },
        "interpretationBoundary": {
            "selectorDomainAcceptedFromD1h": [0, 1],
            "selectorZeroUsesRuntimeName0": True,
            "selectorOneUsesRuntimeName1": True,
            "onlyRuntimeNameInitializerExpressionsReduced": True,
            "onlySafeIdentifiersAndShapeClassesPublished": True,
            "onlyRestrictiveFieldBoundDestinationStringsPublished": True,
            "tableExpressionRecoveryIsNotBootabilityProof": True,
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
    print(json.dumps({
        "classification": data["classification"],
        "oracleSatisfied": data["oracleSatisfied"],
        "derived": data.get("derived", {}),
    }, sort_keys=True))
    return rc


if __name__ == "__main__":
    raise SystemExit(main())
