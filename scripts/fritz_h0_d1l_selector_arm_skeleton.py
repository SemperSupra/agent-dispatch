#!/usr/bin/env python3
"""H0-D1l: recover sanitized syntax skeletons for selector ternary arms.

D1k normalized the linux_fs_start condition but found both new_name ternary arms
were opaque expressions. D1l emits only safe identifier names, structural role
classes, operator-shape classes, and independent occurrence counts for those
identifiers. It does not emit source snippets, literals, offsets, or a selector
to destination mapping.
"""
from __future__ import annotations

import argparse
import importlib.util
import json
import pathlib
import re

_D1K_PATH = pathlib.Path(__file__).with_name("fritz_h0_d1k_selector_ternary_operands.py")
_SPEC = importlib.util.spec_from_file_location("fritz_h0_d1k_selector_ternary_operands", _D1K_PATH)
if _SPEC is None or _SPEC.loader is None:
    raise RuntimeError("unable to load D1k")
d1k = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(d1k)
d1j = d1k.d1j
d1i = d1k.d1i
d1h = d1k.d1h

SCHEMA_VERSION = 1
EXPERIMENT = "fritz-h0-d1l-selector-arm-skeleton/v1"
SELECTOR = "linux_fs_start"
FILES = d1h.FILES
IDENT_TOKEN = re.compile(r"\b[A-Za-z_][A-Za-z0-9_]*\b")
C_KEYWORDS = {
    "if","else","for","while","switch","case","default","return","sizeof",
    "const","char","int","long","unsigned","signed","void","struct","enum",
    "static","volatile","true","false","NULL",
}


def operator_classes(expr: str) -> list[str]:
    classes = []
    probes = [
        ("(", "call_or_group"),
        ("[", "index"),
        ("->", "member_arrow"),
        (".", "member_dot"),
        ("<<", "shift_left"),
        (">>", "shift_right"),
        ("+", "plus"),
        ("-", "minus"),
        ("*", "star"),
        ("/", "divide"),
        ("%", "modulo"),
        ("&", "ampersand"),
        ("|", "pipe"),
        ("^", "xor"),
        ("!", "logical_not"),
    ]
    for token, label in probes:
        if token in expr:
            classes.append(label)
    return sorted(set(classes))


def expression_skeleton(expr: str) -> dict:
    ids = sorted(set(IDENT_TOKEN.findall(expr)) - C_KEYWORDS - {SELECTOR})
    calls = sorted(set(re.findall(r"\b([A-Za-z_][A-Za-z0-9_]*)\s*\(", expr)) - C_KEYWORDS)
    arrays = sorted(set(re.findall(r"\b([A-Za-z_][A-Za-z0-9_]*)\s*\[", expr)))
    members = re.findall(
        r"\b([A-Za-z_][A-Za-z0-9_]*)\s*(?:->|\.)\s*([A-Za-z_][A-Za-z0-9_]*)",
        expr,
    )
    member_bases = sorted({a for a, _ in members})
    member_names = sorted(set(
        [b for _, b in members]
        + re.findall(r"(?:->|\.)\s*([A-Za-z_][A-Za-z0-9_]*)", expr)
    ))
    macro_like = sorted({
        x for x in ids
        if re.fullmatch(r"[A-Z][A-Z0-9_]*", x)
    })

    roles = {}
    for ident in ids:
        r = []
        if ident in calls:
            r.append("function_like_call")
        if ident in arrays:
            r.append("array_base")
        if ident in member_bases:
            r.append("member_base")
        if ident in member_names:
            r.append("member_name")
        if ident in macro_like:
            r.append("macro_like")
        if not r:
            r.append("plain_identifier")
        roles[ident] = sorted(r)

    return {
        "identifierCount": len(ids),
        "identifiers": ids,
        "identifierRoles": roles,
        "operatorClasses": operator_classes(expr),
        "functionLikeCallCount": len(calls),
        "arrayBaseCount": len(arrays),
        "memberRelationCount": len(members),
        "macroLikeCount": len(macro_like),
    }


def recover_arm_skeletons(text: str) -> dict:
    candidates = d1k.selector_assignment_candidates(text)
    decoded = []
    for candidate in candidates:
        ternary = d1k.parse_ternary(candidate["rhs"])
        if ternary is None:
            decoded.append({
                "ternaryRecognized": False,
                "selectorReferenceCount": candidate["selectorReferenceCount"],
            })
            continue
        decoded.append({
            "ternaryRecognized": True,
            "selectorReferenceCount": candidate["selectorReferenceCount"],
            "conditionNormalized": ternary["conditionNormalized"],
            "conditionTruthBySelector": ternary["conditionTruthBySelector"],
            "trueArmSkeleton": expression_skeleton(ternary["trueArm"]),
            "falseArmSkeleton": expression_skeleton(ternary["falseArm"]),
        })
    return {
        "selectorBearingAssignmentCount": len(candidates),
        "decodedAssignmentCount": len(decoded),
        "decoded": decoded,
    }


def identifier_crosscheck(identifiers: list[str], selected: dict[str, str]) -> list[dict]:
    out = []
    for ident in sorted(set(identifiers)):
        files = []
        for path, text in sorted(selected.items()):
            count = len(re.findall(rf"\b{re.escape(ident)}\b", text))
            if count:
                files.append({"file": path, "count": count})
        out.append({
            "identifier": ident,
            "files": files,
            "fileCount": len(files),
            "independentlyObservedOutsideAvmMtd": any(
                not x["file"].endswith("avm_mtd.c") for x in files
            ),
        })
    return out


def classify(recovery: dict, missing: list[str]) -> str:
    if missing:
        return "H0_D1L_SOURCE_MISSING"
    skeletons = [
        x for x in recovery["decoded"]
        if x.get("ternaryRecognized")
        and x.get("trueArmSkeleton")
        and x.get("falseArmSkeleton")
    ]
    if skeletons:
        return "H0_D1L_SELECTOR_ARM_SKELETONS_RECOVERED"
    if recovery["selectorBearingAssignmentCount"] > 0:
        return "H0_D1L_SELECTOR_ARM_SKELETON_PARTIAL"
    return "H0_D1L_SELECTOR_BOUND_ASSIGNMENT_NOT_FOUND"


def run_probe(args):
    work = pathlib.Path(args.work_dir).resolve()
    work.mkdir(parents=True, exist_ok=True)
    archive = work / "source-files.tar.gz"
    exact = d1h.download_exact(
        args.osp_url, archive, args.expected_size, args.expected_sha256
    )
    selected = d1h.extract_selected(archive)
    missing = sorted(set(FILES) - set(selected))
    avm_path = "sources/kernel/linux/drivers/mtd/avm/avm_mtd.c"
    recovery = recover_arm_skeletons(selected.get(avm_path, ""))

    identifiers = [
        ident
        for entry in recovery["decoded"]
        for key in ("trueArmSkeleton", "falseArmSkeleton")
        for ident in entry.get(key, {}).get("identifiers", [])
    ]
    checks = identifier_crosscheck(identifiers, selected)

    return {
        "schemaVersion": SCHEMA_VERSION,
        "experiment": EXPERIMENT,
        "classification": classify(recovery, missing),
        "oracleSatisfied": not missing,
        "sourceArtifact": {
            "expectedBytes": args.expected_size,
            "expectedSha256": args.expected_sha256.lower(),
            "observedBytes": exact["bytes"],
            "observedSha256": exact["sha256"],
        },
        "missingFiles": missing,
        "armRecovery": recovery,
        "identifierCrosscheck": checks,
        "derived": {
            "selectorBearingAssignmentCount": recovery["selectorBearingAssignmentCount"],
            "ternaryRecognizedCount": sum(
                1 for x in recovery["decoded"] if x.get("ternaryRecognized")
            ),
            "conditionNormalizedCount": sum(
                1 for x in recovery["decoded"] if x.get("conditionNormalized")
            ),
            "uniqueArmIdentifierCount": len(set(identifiers)),
            "identifiersObservedOutsideAvmMtdCount": sum(
                1 for x in checks if x["independentlyObservedOutsideAvmMtd"]
            ),
        },
        "interpretationBoundary": {
            "safeIdentifierNamesPublished": True,
            "sourceSnippetsPublished": False,
            "arbitraryLiteralsPublished": False,
            "selectorValueToDestinationMappingAccepted": False,
            "expressionSkeletonIsNotSemanticEquivalenceProof": True,
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
