#!/usr/bin/env python3
"""H0-D1q: falsify or bound the former D1p get_name argument hypothesis."""
from __future__ import annotations

import argparse
import importlib.util
import json
import pathlib
import re

_D1P_PATH = pathlib.Path(__file__).with_name("fritz_h0_d1p_nametable_population.py")
_SPEC = importlib.util.spec_from_file_location("fritz_h0_d1p_nametable_population", _D1P_PATH)
if _SPEC is None or _SPEC.loader is None:
    raise RuntimeError("unable to load D1p")
d1p = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(d1p)
d1h = d1p.d1h

SCHEMA_VERSION = 1
EXPERIMENT = "fritz-h0-d1q-get-name-argument-provenance/v1"
TARGET_PATH = d1p.TARGET_PATH
IDENT = d1p.IDENT
_C_KEYWORDS = d1p._C_KEYWORDS

INTERPRETATION_BOUNDARY = {
    "d1pGetNameHypothesisTested": True,
    "safeIdentifierAndOperatorClassesOnly": True,
    "functionParameterBindingsAccepted": True,
    "nearestLexicalAssignmentIsCandidateOnly": True,
    "controlFlowExecutionAccepted": False,
    "sourceSnippetsAccepted": False,
    "arbitraryStringLiteralsAccepted": False,
    "destinationNamesAccepted": False,
    "numericFlashOffsetsAccepted": False,
    "inactiveSlotSafetyAccepted": False,
    "rollbackSafetyAccepted": False,
    "bootabilityAccepted": False,
    "modifiedHilAuthorized": False,
}


def _matching_paren_forward(masked: str, open_idx: int) -> int | None:
    depth = 0
    for i in range(open_idx, len(masked)):
        ch = masked[i]
        if ch == "(":
            depth += 1
        elif ch == ")":
            depth -= 1
            if depth == 0:
                return i
    return None


def _matching_paren_backward(masked: str, close_idx: int) -> int | None:
    depth = 0
    for i in range(close_idx, -1, -1):
        ch = masked[i]
        if ch == ")":
            depth += 1
        elif ch == "(":
            depth -= 1
            if depth == 0:
                return i
    return None


def _matching_brace_forward(masked: str, open_idx: int) -> int | None:
    depth = 0
    for i in range(open_idx, len(masked)):
        ch = masked[i]
        if ch == "{":
            depth += 1
        elif ch == "}":
            depth -= 1
            if depth == 0:
                return i
    return None


def _parameter_names(params: str) -> list[str]:
    out = []
    for part in d1p.d1o.d1m.split_top_level(params):
        masked = d1h.mask_comments_strings(part).strip()
        if not masked or masked == "void":
            continue
        names = re.findall(rf"\b({IDENT})\b", masked)
        names = [n for n in names if n not in _C_KEYWORDS]
        if not names:
            continue
        candidate = names[-1]
        if candidate not in out:
            out.append(candidate)
    return out


def function_spans(text: str) -> list[dict]:
    """Find only top-level C function bodies with sanitized signature metadata."""
    masked = d1h.mask_comments_strings(text)
    out = []
    depth = 0
    i = 0
    while i < len(masked):
        ch = masked[i]
        if ch == "{":
            if depth == 0:
                j = i - 1
                while j >= 0 and masked[j].isspace():
                    j -= 1
                if j >= 0 and masked[j] == ")":
                    open_idx = _matching_paren_backward(masked, j)
                    if open_idx is not None:
                        k = open_idx - 1
                        while k >= 0 and masked[k].isspace():
                            k -= 1
                        end_name = k + 1
                        while k >= 0 and (masked[k].isalnum() or masked[k] == "_"):
                            k -= 1
                        name = masked[k + 1:end_name]
                        if name and name not in _C_KEYWORDS:
                            close_brace = _matching_brace_forward(masked, i)
                            if close_brace is not None:
                                params = text[open_idx + 1:j]
                                out.append({
                                    "name": name,
                                    "parameterNames": _parameter_names(params),
                                    "parameterCount": len(d1p.d1o.d1m.split_top_level(params))
                                    if params.strip() and params.strip() != "void" else 0,
                                    "_bodyStart": i,
                                    "_bodyEnd": close_brace,
                                })
            depth += 1
        elif ch == "}":
            depth = max(0, depth - 1)
        i += 1
    return out


def _enclosing_function(spans: list[dict], position: int) -> dict | None:
    for span in spans:
        if span["_bodyStart"] < position < span["_bodyEnd"]:
            return span
    return None


def _get_name_calls(text: str) -> list[dict]:
    masked = d1h.mask_comments_strings(text)
    spans = function_spans(text)
    out = []
    rx = re.compile(r"\bget_name\s*\(")
    for m in rx.finditer(masked):
        open_idx = masked.find("(", m.start(), m.end())
        close_idx = _matching_paren_forward(masked, open_idx)
        if close_idx is None:
            continue

        # Exclude a function definition rather than treating its parameter list as a call.
        j = close_idx + 1
        while j < len(masked) and masked[j].isspace():
            j += 1
        if j < len(masked) and masked[j] == "{":
            continue

        args = d1p.d1o.d1m.split_top_level(text[open_idx + 1:close_idx])
        for idx, arg in enumerate(args):
            if not re.search(r"\bnametable\b", d1h.mask_comments_strings(arg)):
                continue
            fn = _enclosing_function(spans, m.start())
            skeleton = d1p.expression_skeleton(arg)
            out.append({
                "argumentIndex": idx,
                "argumentSkeleton": skeleton,
                "enclosingFunction": None if fn is None else {
                    "name": fn["name"],
                    "parameterNames": fn["parameterNames"],
                    "parameterCount": fn["parameterCount"],
                },
                "_callStart": m.start(),
                "_bodyStart": None if fn is None else fn["_bodyStart"],
            })
    return out


def _assignment_candidates(text: str, body_start: int, call_start: int, name: str) -> list[dict]:
    prefix = text[body_start + 1:call_start]
    masked = d1h.mask_comments_strings(prefix)
    rx = re.compile(rf"\b{re.escape(name)}\b\s*=(?!=)")
    out = []
    for m in rx.finditer(masked):
        rhs = d1p._statement_rhs(prefix, m.end())
        out.append({"rhs": d1p.expression_skeleton(rhs)})
    return out


def _trace_identifier(text: str, call: dict, ident: dict) -> dict:
    name = ident["name"]
    roles = ident["roles"]
    fn = call.get("enclosingFunction") or {}
    params = fn.get("parameterNames") or []
    if name in params:
        return {
            "name": name,
            "roles": roles,
            "relation": "function_parameter",
            "assignmentCandidateCount": 0,
            "nearestAssignmentRhs": None,
        }

    body_start = call.get("_bodyStart")
    call_start = call.get("_callStart")
    assignments = []
    if isinstance(body_start, int) and isinstance(call_start, int):
        assignments = _assignment_candidates(text, body_start, call_start, name)
    if assignments:
        return {
            "name": name,
            "roles": roles,
            "relation": "nearest_lexical_assignment_candidate",
            "assignmentCandidateCount": len(assignments),
            "nearestAssignmentRhs": assignments[-1]["rhs"],
        }

    return {
        "name": name,
        "roles": roles,
        "relation": "unresolved",
        "assignmentCandidateCount": 0,
        "nearestAssignmentRhs": None,
    }


def local_get_name_definitions(text: str) -> list[dict]:
    return [
        {
            "name": span["name"],
            "parameterNames": span["parameterNames"],
            "parameterCount": span["parameterCount"],
        }
        for span in function_spans(text)
        if span["name"] == "get_name"
    ]


def analyze_target(text: str) -> dict:
    calls = _get_name_calls(text)
    durable_calls = []
    for call in calls:
        tracked = []
        for ident in call["argumentSkeleton"]["identifiers"]:
            if ident["name"] == "nametable":
                continue
            # Member names describe the expression shape but are not local producers.
            if "member" in ident["roles"]:
                continue
            tracked.append(_trace_identifier(text, call, ident))
        durable_calls.append({
            "argumentIndex": call["argumentIndex"],
            "argumentSkeleton": call["argumentSkeleton"],
            "enclosingFunction": call["enclosingFunction"],
            "trackedIdentifiers": tracked,
            "resolvedTrackedIdentifierCount": sum(
                1 for item in tracked if item["relation"] != "unresolved"
            ),
            "unresolvedTrackedIdentifierCount": sum(
                1 for item in tracked if item["relation"] == "unresolved"
            ),
        })

    definitions = local_get_name_definitions(text)
    return {
        "getNameNametableCallsiteCount": len(durable_calls),
        "calls": durable_calls,
        "localGetNameDefinitionCount": len(definitions),
        "localGetNameDefinitions": definitions,
    }


def classify(a: dict) -> str:
    count = a["getNameNametableCallsiteCount"]
    if count == 0:
        return "H0_D1Q_GET_NAME_EDGE_NOT_REPRODUCED"
    if count != 1:
        return "H0_D1Q_GET_NAME_ARGUMENT_AMBIGUOUS"
    call = a["calls"][0]
    tracked = call["trackedIdentifiers"]
    if tracked and call["unresolvedTrackedIdentifierCount"] == 0:
        return "H0_D1Q_GET_NAME_LOCAL_PROVENANCE_RECOVERED"
    if call["resolvedTrackedIdentifierCount"]:
        return "H0_D1Q_GET_NAME_LOCAL_PROVENANCE_PARTIAL"
    return "H0_D1Q_GET_NAME_ARGUMENT_SKELETON_RECOVERED"


def run_probe(args):
    work = pathlib.Path(args.work_dir).resolve()
    work.mkdir(parents=True, exist_ok=True)
    archive = work / "source-files.tar.gz"
    exact = d1p.d1h.download_exact(
        args.osp_url, archive, args.expected_size, args.expected_sha256
    )
    text = d1p.extract_target(archive)
    analysis = analyze_target(text)
    return {
        "schemaVersion": SCHEMA_VERSION,
        "experiment": EXPERIMENT,
        "classification": classify(analysis),
        "oracleSatisfied": True,
        "sourceArtifact": {
            "expectedBytes": args.expected_size,
            "expectedSha256": args.expected_sha256.lower(),
            "observedBytes": exact["bytes"],
            "observedSha256": exact["sha256"],
        },
        "targetPath": TARGET_PATH,
        "argumentProvenance": analysis,
        "interpretationBoundary": dict(INTERPRETATION_BOUNDARY),
        "safety": {
            "rawOspArchivePublished": False,
            "sourcePayloadPublished": False,
            "sourceSnippetsPublished": False,
            "arbitraryStringLiteralsPublished": False,
            "destinationNamesPublished": False,
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
                "destinationNamesPublished": False,
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
        "argumentProvenance": data.get("argumentProvenance", {}),
    }, sort_keys=True))
    return rc


if __name__ == "__main__":
    raise SystemExit(main())
