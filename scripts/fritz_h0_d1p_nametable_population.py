#!/usr/bin/env python3
"""H0-D1p: recover how AVM MTD nametable is populated after declaration."""
from __future__ import annotations

import argparse
import importlib.util
import json
import pathlib
import re
import tarfile

_D1O_PATH = pathlib.Path(__file__).with_name("fritz_h0_d1o_nametable_provenance.py")
_SPEC = importlib.util.spec_from_file_location("fritz_h0_d1o_nametable_provenance", _D1O_PATH)
if _SPEC is None or _SPEC.loader is None:
    raise RuntimeError("unable to load D1o")
d1o = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(d1o)
d1h = d1o.d1h

SCHEMA_VERSION = 1
EXPERIMENT = "fritz-h0-d1p-nametable-population/v1"
TARGET_PATH = "sources/kernel/linux/drivers/mtd/avm/avm_mtd.c"
IDENT = r"[A-Za-z_][A-Za-z0-9_]*"
_C_KEYWORDS = {
    "auto","break","case","char","const","continue","default","do","double",
    "else","enum","extern","float","for","goto","if","inline","int","long",
    "register","restrict","return","short","signed","sizeof","static","struct",
    "switch","typedef","union","unsigned","void","volatile","while",
}

INTERPRETATION_BOUNDARY = {
    "declarationShapeAccepted": True,
    "assignmentAndCallShapesAreCandidateEvidenceOnly": True,
    "safeIdentifiersAndOperatorClassesOnly": True,
    "sourceSnippetsAccepted": False,
    "arbitraryStringLiteralsAccepted": False,
    "numericFlashOffsetsAccepted": False,
    "inactiveSlotSafetyAccepted": False,
    "rollbackSafetyAccepted": False,
    "modifiedHilAuthorized": False,
}


def extract_target(archive: pathlib.Path) -> str:
    with tarfile.open(archive, "r:*") as tf:
        for member in tf:
            if not member.isfile():
                continue
            if d1o.normalize_member_name(member.name) != TARGET_PATH:
                continue
            fp = tf.extractfile(member)
            if fp is None:
                break
            return fp.read().decode("utf-8", errors="replace")
    raise RuntimeError("target AVM MTD source missing")


def _operator_classes(masked: str) -> list[str]:
    probes = (
        ("call", rf"\b{IDENT}\s*\("),
        ("array_index", r"\[[^\]]*\]"),
        ("member", r"(?:->|\.)\s*[A-Za-z_]"),
        ("address_of", r"(^|[^&])&\s*[A-Za-z_(]"),
        ("dereference", r"(^|[^*/])\*\s*[A-Za-z_(]"),
        ("ternary", r"\?.*:"),
        ("arithmetic", r"[+\-*/%]"),
        ("logical", r"(?:&&|\|\||!)"),
        ("comparison", r"(?:==|!=|<=|>=|<|>)"),
        ("bitwise", r"(?:<<|>>|\^|\||&)"),
    )
    return [name for name, rx in probes if re.search(rx, masked)]


def expression_skeleton(expr: str) -> dict:
    masked = d1h.mask_comments_strings(expr)
    identifiers = []
    seen = set()
    for m in re.finditer(rf"\b(?P<name>{IDENT})\b", masked):
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
    root_call = re.match(rf"\s*(?P<fn>{IDENT})\s*\(", masked)
    return {
        "identifiers": identifiers,
        "operatorClasses": _operator_classes(masked),
        "rootCallIdentifier": root_call.group("fn") if root_call else None,
        "stringLiteralCount": len(re.findall(r'["\']', expr)) // 2,
    }


def _statement_rhs(text: str, start: int) -> str:
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
        if ch == ";" and all(v == 0 for v in depth.values()):
            return text[start:i].strip()
    return text[start:].strip()


def declaration_shape(text: str) -> dict:
    masked = d1h.mask_comments_strings(text)
    rx = re.compile(
        rf"""(?x)
        \b(?P<storage>extern|static)?\s*
        (?:(?:const|volatile)\s+)*
        struct\s+mtd_entry
        \s+(?P<stars>\*+\s*)?
        nametable\b
        (?P<tail>[^;]*);
        """
    )
    matches = []
    for m in rx.finditer(masked):
        tail = m.group("tail")
        matches.append({
            "storageClass": m.group("storage") or "none",
            "pointerDepth": (m.group("stars") or "").count("*"),
            "arrayDeclarator": bool(re.search(r"\[[^\]]*\]", tail)),
            "hasInitializer": bool(re.search(r"(?<![=!<>])=(?!=)", tail)),
        })
    return {"candidateCount": len(matches), "candidates": matches}


def direct_assignments(text: str) -> list[dict]:
    masked = d1h.mask_comments_strings(text)
    out = []
    rx = re.compile(r"(?<![A-Za-z0-9_.>])\bnametable\b\s*=(?!=)")
    for m in rx.finditer(masked):
        rhs = _statement_rhs(text, m.end())
        out.append({"rhs": expression_skeleton(rhs)})
    return out


def member_writes(text: str) -> list[dict]:
    masked = d1h.mask_comments_strings(text)
    rx = re.compile(
        rf"\bnametable\s*\[(?P<index>[^\]]+)\]\s*(?:\.|->)\s*"
        rf"(?P<field>{IDENT})\s*=(?!=)"
    )
    out = []
    for m in rx.finditer(masked):
        rhs = _statement_rhs(text, m.end())
        out.append({
            "field": m.group("field"),
            "index": expression_skeleton(m.group("index")),
            "rhs": expression_skeleton(rhs),
        })
    return out


def call_edges(text: str) -> list[dict]:
    masked = d1h.mask_comments_strings(text)
    out = []
    # Bounded lexical call scan; only calls whose argument span contains
    # the target identifier are retained.
    rx = re.compile(rf"\b(?P<fn>{IDENT})\s*\(")
    for m in rx.finditer(masked):
        fn = m.group("fn")
        if fn in _C_KEYWORDS:
            continue
        open_idx = masked.find("(", m.start(), m.end())
        depth = 0
        close_idx = None
        for i in range(open_idx, min(len(masked), open_idx + 8192)):
            ch = masked[i]
            if ch == "(":
                depth += 1
            elif ch == ")":
                depth -= 1
                if depth == 0:
                    close_idx = i
                    break
        if close_idx is None:
            continue
        arg_text = masked[open_idx + 1:close_idx]
        if not re.search(r"\bnametable\b", arg_text):
            continue
        args = d1o.d1m.split_top_level(text[open_idx + 1:close_idx])
        positions = [
            idx for idx, arg in enumerate(args)
            if re.search(r"\bnametable\b", d1h.mask_comments_strings(arg))
        ]
        out.append({
            "callIdentifier": fn,
            "nametableArgumentIndexes": positions,
            "argumentSkeletons": [
                expression_skeleton(args[idx]) for idx in positions
            ],
        })
    # exact de-duplication without source-position publication
    unique = []
    seen = set()
    for item in out:
        key = json.dumps(item, sort_keys=True)
        if key in seen:
            continue
        seen.add(key)
        unique.append(item)
    return unique


def analyze_target(text: str) -> dict:
    decl = declaration_shape(text)
    assigns = direct_assignments(text)
    writes = member_writes(text)
    calls = call_edges(text)
    producer_ids = sorted({
        ident["name"]
        for rec in assigns
        for ident in rec["rhs"]["identifiers"]
    })
    return {
        "declaration": decl,
        "directAssignments": assigns,
        "memberWrites": writes,
        "callEdges": calls,
        "producerIdentifiers": producer_ids,
        "derived": {
            "directAssignmentCount": len(assigns),
            "memberWriteCount": len(writes),
            "callEdgeCount": len(calls),
            "uniqueProducerIdentifierCount": len(producer_ids),
        },
    }


def classify(a: dict) -> str:
    d = a["derived"]
    if d["directAssignmentCount"]:
        return "H0_D1P_DIRECT_ASSIGNMENT_PRODUCER_LOCATED"
    if d["memberWriteCount"]:
        return "H0_D1P_MEMBER_POPULATION_LOCATED"
    if d["callEdgeCount"]:
        return "H0_D1P_CALL_EDGE_PRODUCER_CANDIDATE_LOCATED"
    return "H0_D1P_NO_LOCAL_POPULATION_EDGE"


def run_probe(args):
    work = pathlib.Path(args.work_dir).resolve()
    work.mkdir(parents=True, exist_ok=True)
    archive = work / "source-files.tar.gz"
    exact = d1h.download_exact(
        args.osp_url, archive, args.expected_size, args.expected_sha256
    )
    text = extract_target(archive)
    analysis = analyze_target(text)
    return {
        "schemaVersion": SCHEMA_VERSION,
        "experiment": EXPERIMENT,
        "classification": classify(analysis),
        "oracleSatisfied": analysis["declaration"]["candidateCount"] == 1,
        "sourceArtifact": {
            "expectedBytes": args.expected_size,
            "expectedSha256": args.expected_sha256.lower(),
            "observedBytes": exact["bytes"],
            "observedSha256": exact["sha256"],
        },
        "targetPath": TARGET_PATH,
        "population": analysis,
        "interpretationBoundary": dict(INTERPRETATION_BOUNDARY),
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
        "population": data.get("population", {}),
    }, sort_keys=True))
    return rc


if __name__ == "__main__":
    raise SystemExit(main())
