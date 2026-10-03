#!/usr/bin/env python3
"""H0-D1k: decode the selector-bearing new_name ternary operands.

D1j recovered one exact new_name assignment after the selector switch whose RHS
references linux_fs_start once and has equality + ternary structure, but whose
arms are not direct safe strings. D1k decodes only that bounded assignment.

Identifier arms are resolved to destination strings only when the selected source
contains exactly one mechanically recognized write for that identifier and that
write is a direct restrictive string initializer/assignment, or when the
identifier has exactly one direct restrictive string #define and no writes.
Anything else remains unresolved.
"""
from __future__ import annotations

import argparse
import importlib.util
import json
import pathlib
import re

_D1J_PATH = pathlib.Path(__file__).with_name("fritz_h0_d1j_selector_assignment_context.py")
_SPEC = importlib.util.spec_from_file_location("fritz_h0_d1j_selector_assignment_context", _D1J_PATH)
if _SPEC is None or _SPEC.loader is None:
    raise RuntimeError("unable to load D1j")
d1j = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(d1j)
d1i = d1j.d1i
d1h = d1j.d1h

SCHEMA_VERSION = 1
EXPERIMENT = "fritz-h0-d1k-selector-ternary-operands/v1"
SELECTOR = "linux_fs_start"
DEST_LHS = "new_name"
FILES = d1h.FILES
IDENT_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")
SAFE_DEST_RE = d1h.SAFE_DEST_RE
_QUOTED_FULL_RE = re.compile(r'^\s*["\'](?P<value>[^"\']+)["\']\s*$')
_TERNARY_RE = re.compile(
    r"^\s*(?P<cond>.+?)\s*\?\s*(?P<t>.+?)\s*:\s*(?P<f>.+?)\s*$",
    re.S,
)


def selector_assignment_candidates(text: str) -> list[dict]:
    masked = d1h.mask_comments_strings(text)
    out = []
    for m in d1j._ASSIGN_START_RE.finditer(masked):
        end = d1j.statement_end(text, m.end())
        if end is None:
            continue
        statement = text[m.start(): end + 1]
        masked_statement = d1h.mask_comments_strings(statement)
        eq = statement.find("=")
        meq = masked_statement.find("=")
        if eq < 0 or meq < 0:
            continue
        rhs = statement[eq + 1:-1].strip()
        rhs_masked = masked_statement[meq + 1:-1]
        selector_refs = len(re.findall(rf"\b{SELECTOR}\b", rhs_masked))
        if selector_refs <= 0:
            continue
        out.append({
            "statementStart": m.start(),
            "selectorReferenceCount": selector_refs,
            "rhs": rhs,
        })
    return out


def direct_safe_string(expr: str) -> str | None:
    m = _QUOTED_FULL_RE.fullmatch(d1i._strip_outer_parens(expr))
    if not m:
        return None
    value = m.group("value")
    return value if SAFE_DEST_RE.fullmatch(value) else None


def parse_ternary(rhs: str) -> dict | None:
    m = _TERNARY_RE.fullmatch(rhs)
    if not m:
        return None
    cond = d1i._strip_outer_parens(m.group("cond"))
    truth = d1i.normalize_condition(cond)
    return {
        "conditionNormalized": truth is not None,
        "conditionTruthBySelector": (
            {str(k): v for k, v in sorted(truth.items())}
            if truth is not None else None
        ),
        "trueArm": m.group("t").strip(),
        "falseArm": m.group("f").strip(),
    }


def assignment_writes(text: str, identifier: str) -> list[dict]:
    masked = d1h.mask_comments_strings(text)
    rx = re.compile(rf"\b{re.escape(identifier)}\s*=(?!=)")
    out = []
    for m in rx.finditer(masked):
        end = d1j.statement_end(text, m.end())
        if end is None:
            out.append({"statementClosed": False, "directSafeString": None})
            continue
        statement = text[m.start():end + 1]
        eq = statement.find("=")
        rhs = statement[eq + 1:-1].strip() if eq >= 0 else ""
        out.append({
            "statementClosed": True,
            "directSafeString": direct_safe_string(rhs),
        })
    return out


def macro_string_definitions(text: str, identifier: str) -> list[str]:
    masked = d1h.mask_comments_strings(text)
    original_lines = text.splitlines()
    masked_lines = masked.splitlines()
    out = []
    for original, masked_line in zip(original_lines, masked_lines):
        if not re.match(rf"^\s*#\s*define\s+{re.escape(identifier)}\b", masked_line):
            continue
        m = re.match(
            rf"^\s*#\s*define\s+{re.escape(identifier)}\s+([\"'])(?P<value>[^\"']+)\1\s*$",
            original,
        )
        if m and SAFE_DEST_RE.fullmatch(m.group("value")):
            out.append(m.group("value"))
    return out


def resolve_identifier(text: str, identifier: str) -> dict:
    writes = assignment_writes(text, identifier)
    macros = macro_string_definitions(text, identifier)

    direct_write_strings = [
        x["directSafeString"] for x in writes if x.get("directSafeString") is not None
    ]
    resolved = None
    method = None
    if len(writes) == 1 and len(direct_write_strings) == 1 and not macros:
        resolved = direct_write_strings[0]
        method = "unique_direct_string_write"
    elif not writes and len(macros) == 1:
        resolved = macros[0]
        method = "unique_direct_string_macro"

    return {
        "identifier": identifier,
        "writeCount": len(writes),
        "directSafeStringWriteCount": len(direct_write_strings),
        "safeStringMacroCount": len(macros),
        "resolvedDestination": resolved,
        "resolutionMethod": method,
        "uniquelyResolved": resolved is not None,
    }


def arm_summary(text: str, arm: str) -> dict:
    arm = d1i._strip_outer_parens(arm)
    direct = direct_safe_string(arm)
    if direct is not None:
        return {
            "kind": "safe_destination_string",
            "safeIdentifier": None,
            "resolvedDestination": direct,
            "resolutionMethod": "direct_string_arm",
        }
    if IDENT_RE.fullmatch(arm):
        resolution = resolve_identifier(text, arm)
        return {
            "kind": "safe_identifier",
            "safeIdentifier": arm,
            "resolvedDestination": resolution["resolvedDestination"],
            "resolutionMethod": resolution["resolutionMethod"],
            "identifierResolution": resolution,
        }
    identifiers = sorted(set(re.findall(r"\b[A-Za-z_][A-Za-z0-9_]*\b", arm)))
    return {
        "kind": "opaque_expression",
        "safeIdentifier": None,
        "resolvedDestination": None,
        "resolutionMethod": None,
        "identifierCount": len(identifiers),
        "containsSelector": SELECTOR in identifiers,
    }


def recover_mapping(text: str) -> dict:
    candidates = selector_assignment_candidates(text)
    decoded = []
    for candidate in candidates:
        ternary = parse_ternary(candidate["rhs"])
        if ternary is None:
            decoded.append({
                "selectorReferenceCount": candidate["selectorReferenceCount"],
                "ternaryRecognized": False,
            })
            continue
        true_arm = arm_summary(text, ternary["trueArm"])
        false_arm = arm_summary(text, ternary["falseArm"])

        mapping = None
        truth = ternary["conditionTruthBySelector"]
        if (
            truth is not None
            and true_arm.get("resolvedDestination") is not None
            and false_arm.get("resolvedDestination") is not None
        ):
            mapping = {
                value: (
                    true_arm["resolvedDestination"]
                    if predicate_true
                    else false_arm["resolvedDestination"]
                )
                for value, predicate_true in truth.items()
            }

        decoded.append({
            "selectorReferenceCount": candidate["selectorReferenceCount"],
            "ternaryRecognized": True,
            "conditionNormalized": ternary["conditionNormalized"],
            "conditionTruthBySelector": ternary["conditionTruthBySelector"],
            "trueArm": true_arm,
            "falseArm": false_arm,
            "normalizedCaseMapping": mapping,
        })

    return {
        "selectorBearingAssignmentCount": len(candidates),
        "decodedAssignmentCount": len(decoded),
        "decoded": decoded,
    }


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


def classify(recovery: dict, checks: list[dict], missing: list[str]) -> str:
    if missing:
        return "H0_D1K_SOURCE_MISSING"
    mappings = [
        x["normalizedCaseMapping"]
        for x in recovery["decoded"]
        if x.get("normalizedCaseMapping")
    ]
    if mappings:
        destinations = {v for m in mappings for v in m.values()}
        checked = {x["destination"] for x in checks}
        if (
            destinations
            and checked == destinations
            and all(x["independentlyObserved"] for x in checks)
        ):
            return "H0_D1K_SELECTOR_DESTINATION_MAPPING_CROSSCHECKED"
        return "H0_D1K_SELECTOR_DESTINATION_MAPPING_CROSSCHECK_PARTIAL"
    if any(x.get("ternaryRecognized") for x in recovery["decoded"]):
        return "H0_D1K_SELECTOR_TERNARY_OPERANDS_RECOVERED"
    if recovery["selectorBearingAssignmentCount"] > 0:
        return "H0_D1K_SELECTOR_ASSIGNMENT_TERNARY_PARTIAL"
    return "H0_D1K_SELECTOR_BOUND_ASSIGNMENT_NOT_FOUND"


def run_probe(args):
    work = pathlib.Path(args.work_dir).resolve()
    work.mkdir(parents=True, exist_ok=True)
    archive = work / "source-files.tar.gz"
    exact = d1h.download_exact(
        args.osp_url,
        archive,
        args.expected_size,
        args.expected_sha256,
    )
    selected = d1h.extract_selected(archive)
    missing = sorted(set(FILES) - set(selected))
    avm_path = "sources/kernel/linux/drivers/mtd/avm/avm_mtd.c"
    recovery = recover_mapping(selected.get(avm_path, ""))

    destinations = [
        dest
        for entry in recovery["decoded"]
        for mapping in ([entry.get("normalizedCaseMapping")] if entry.get("normalizedCaseMapping") else [])
        for dest in mapping.values()
    ]
    checks = crosscheck(destinations, selected)
    classification = classify(recovery, checks, missing)

    resolved_identifier_arms = sum(
        1
        for entry in recovery["decoded"]
        for key in ("trueArm", "falseArm")
        if entry.get(key, {}).get("kind") == "safe_identifier"
        and entry[key].get("resolvedDestination") is not None
    )
    unresolved_identifier_arms = sum(
        1
        for entry in recovery["decoded"]
        for key in ("trueArm", "falseArm")
        if entry.get(key, {}).get("kind") == "safe_identifier"
        and entry[key].get("resolvedDestination") is None
    )

    return {
        "schemaVersion": SCHEMA_VERSION,
        "experiment": EXPERIMENT,
        "classification": classification,
        "oracleSatisfied": not missing,
        "sourceArtifact": {
            "expectedBytes": args.expected_size,
            "expectedSha256": args.expected_sha256.lower(),
            "observedBytes": exact["bytes"],
            "observedSha256": exact["sha256"],
        },
        "missingFiles": missing,
        "ternaryRecovery": recovery,
        "destinationCrosscheck": checks,
        "derived": {
            "selectorBearingAssignmentCount": recovery["selectorBearingAssignmentCount"],
            "ternaryRecognizedCount": sum(
                1 for x in recovery["decoded"] if x.get("ternaryRecognized")
            ),
            "conditionNormalizedCount": sum(
                1 for x in recovery["decoded"] if x.get("conditionNormalized")
            ),
            "resolvedIdentifierArmCount": resolved_identifier_arms,
            "unresolvedIdentifierArmCount": unresolved_identifier_arms,
            "normalizedMappingCount": sum(
                1 for x in recovery["decoded"] if x.get("normalizedCaseMapping")
            ),
            "destinationCount": len(set(destinations)),
            "independentlyObservedDestinationCount": sum(
                1 for x in checks if x["independentlyObserved"]
            ),
        },
        "interpretationBoundary": {
            "selectorDomainAcceptedFromD1h": [0, 1],
            "onlySelectorBearingNewNameAssignmentsDecoded": True,
            "identifierDestinationRequiresUniqueDirectStringDefinition": True,
            "ambiguousIdentifierDefinitionRemainsUnresolved": True,
            "destinationNameMatchIsNotBootabilityProof": True,
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
    print(json.dumps(
        {"classification": data["classification"], "oracleSatisfied": data["oracleSatisfied"]},
        sort_keys=True,
    ))
    return rc


if __name__ == "__main__":
    raise SystemExit(main())
