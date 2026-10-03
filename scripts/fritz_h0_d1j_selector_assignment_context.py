#!/usr/bin/env python3
"""H0-D1j: recover whole-file new_name assignment context around linux_fs_start.

D1i falsified the specific hypothesis that a selector-bearing new_name assignment
exists in the same enclosing block after switch(linux_fs_start). D1j removes that
location assumption. It inventories exact new_name assignments across the selected
AVM MTD source and emits only structural context, selector-reference counts,
operator classes, and restrictive destination-like strings mechanically bound to
that LHS.

No selector-value -> destination mapping is accepted in this step.
"""
from __future__ import annotations

import argparse
import importlib.util
import json
import pathlib
import re

_D1I_PATH = pathlib.Path(__file__).with_name("fritz_h0_d1i_selector_destination.py")
_SPEC = importlib.util.spec_from_file_location("fritz_h0_d1i_selector_destination", _D1I_PATH)
if _SPEC is None or _SPEC.loader is None:
    raise RuntimeError("unable to load D1i")
d1i = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(d1i)
d1h = d1i.d1h

SCHEMA_VERSION = 1
EXPERIMENT = "fritz-h0-d1j-selector-assignment-context/v1"
SELECTOR = "linux_fs_start"
DEST_LHS = "new_name"
FILES = d1h.FILES
SAFE_DEST_RE = d1h.SAFE_DEST_RE

_ASSIGN_START_RE = re.compile(r"\bnew_name\s*=")
_STRING_RE = re.compile(r'["\']([^"\']+)["\']')


def brace_depth(masked: str, pos: int) -> int:
    depth = 0
    for ch in masked[:pos]:
        if ch == "{":
            depth += 1
        elif ch == "}":
            depth = max(0, depth - 1)
    return depth


def enclosing_block_span(text: str, masked: str, pos: int) -> tuple[int | None, int | None]:
    stack: list[int] = []
    for i, ch in enumerate(masked[:pos]):
        if ch == "{":
            stack.append(i)
        elif ch == "}" and stack:
            stack.pop()
    if not stack:
        return None, None
    open_idx = stack[-1]
    return open_idx, d1h.match_brace(text, open_idx)


def statement_end(text: str, start: int) -> int | None:
    quote = None
    escape = False
    paren = bracket = brace = 0
    i = start
    while i < len(text):
        ch = text[i]
        if quote:
            if escape:
                escape = False
            elif ch == "\\":
                escape = True
            elif ch == quote:
                quote = None
            i += 1
            continue
        if ch in {'"', "'"}:
            quote = ch
        elif ch == "(":
            paren += 1
        elif ch == ")":
            paren = max(0, paren - 1)
        elif ch == "[":
            bracket += 1
        elif ch == "]":
            bracket = max(0, bracket - 1)
        elif ch == "{":
            brace += 1
        elif ch == "}":
            brace = max(0, brace - 1)
        elif ch == ";" and paren == 0 and bracket == 0 and brace == 0:
            return i
        i += 1
    return None


def safe_strings(rhs: str) -> list[str]:
    vals = []
    for m in _STRING_RE.finditer(rhs):
        value = m.group(1)
        if SAFE_DEST_RE.fullmatch(value):
            vals.append(value)
    return sorted(set(vals))


def selector_operator_classes(rhs_masked: str) -> list[str]:
    out = []
    for op, label in (
        ("==", "eq"),
        ("!=", "ne"),
        ("<=", "le"),
        (">=", "ge"),
        ("<", "lt"),
        (">", "gt"),
        ("?", "ternary"),
        ("!", "logical_not"),
        ("&", "bit_and"),
        ("|", "bit_or"),
    ):
        if op in rhs_masked:
            out.append(label)
    return sorted(set(out))


def switch_context(text: str, masked: str) -> dict:
    sm = d1i._SWITCH_RE.search(masked)
    if not sm:
        return {
            "switchFound": False,
            "switchClosed": False,
            "start": None,
            "open": None,
            "close": None,
            "enclosingDepth": None,
            "enclosingOpen": None,
            "enclosingClose": None,
        }
    open_idx = masked.find("{", sm.start(), sm.end())
    close_idx = d1h.match_brace(text, open_idx)
    enclosing_open, enclosing_close = enclosing_block_span(text, masked, sm.start())
    return {
        "switchFound": True,
        "switchClosed": close_idx is not None,
        "start": sm.start(),
        "open": open_idx,
        "close": close_idx,
        "enclosingDepth": brace_depth(masked, open_idx),
        "enclosingOpen": enclosing_open,
        "enclosingClose": enclosing_close,
    }


def relative_to_switch(pos: int, sw: dict) -> str:
    if not sw["switchFound"]:
        return "switch_not_found"
    if sw["close"] is None:
        return "switch_unclosed"
    if pos < sw["start"]:
        return "before_switch"
    if sw["open"] <= pos <= sw["close"]:
        return "inside_switch"
    return "after_switch"


def assignment_contexts(text: str) -> dict:
    masked = d1h.mask_comments_strings(text)
    sw = switch_context(text, masked)
    contexts = []

    for m in _ASSIGN_START_RE.finditer(masked):
        end = statement_end(text, m.end())
        if end is None:
            contexts.append({
                "lhs": DEST_LHS,
                "statementClosed": False,
                "relativeToSelectorSwitch": relative_to_switch(m.start(), sw),
            })
            continue

        statement = text[m.start():end + 1]
        eq = statement.find("=")
        rhs = statement[eq + 1:-1] if eq >= 0 else ""
        masked_statement = d1h.mask_comments_strings(statement)
        masked_eq = masked_statement.find("=")
        rhs_masked = masked_statement[masked_eq + 1:-1] if masked_eq >= 0 else ""

        selector_refs = len(re.findall(rf"\b{SELECTOR}\b", rhs_masked))
        depth = brace_depth(masked, m.start())
        same_enclosing = (
            sw["switchFound"]
            and sw["switchClosed"]
            and sw.get("enclosingOpen") is not None
            and sw.get("enclosingClose") is not None
            and sw["enclosingOpen"] < m.start() < sw["enclosingClose"]
        )
        destinations = safe_strings(rhs)

        contexts.append({
            "lhs": DEST_LHS,
            "statementClosed": True,
            "relativeToSelectorSwitch": relative_to_switch(m.start(), sw),
            "sameEnclosingBlockAsSelectorSwitch": bool(same_enclosing),
            "selectorReferenceCount": selector_refs,
            "selectorOperatorClasses": selector_operator_classes(rhs_masked) if selector_refs else [],
            "safeDestinationTokens": destinations,
            "safeDestinationCount": len(destinations),
            "simpleSelectorTernaryRecognized": bool(
                selector_refs and d1i.ternary_mapping(rhs) is not None
            ),
        })

    return {
        "switchFound": sw["switchFound"],
        "switchClosed": sw["switchClosed"],
        "assignmentCount": len(contexts),
        "selectorBearingAssignmentCount": sum(
            1 for x in contexts if x.get("selectorReferenceCount", 0) > 0
        ),
        "contexts": contexts,
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


def classify(inv: dict, missing: list[str]) -> str:
    if missing:
        return "H0_D1J_SOURCE_MISSING"
    if inv["selectorBearingAssignmentCount"] > 0:
        return "H0_D1J_SELECTOR_BOUND_ASSIGNMENT_CONTEXT_RECOVERED"
    if inv["assignmentCount"] > 0:
        return "H0_D1J_NEW_NAME_ASSIGNMENT_CONTEXT_RECOVERED"
    if inv["switchFound"]:
        return "H0_D1J_NEW_NAME_ASSIGNMENT_NOT_FOUND"
    return "H0_D1J_SELECTOR_SWITCH_NOT_FOUND"


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
    inv = assignment_contexts(selected.get(avm_path, ""))

    destinations = [
        token
        for ctx in inv["contexts"]
        for token in ctx.get("safeDestinationTokens", [])
    ]
    checks = crosscheck(destinations, selected)
    classification = classify(inv, missing)

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
        "assignmentInventory": inv,
        "destinationCrosscheck": checks,
        "derived": {
            "assignmentCount": inv["assignmentCount"],
            "selectorBearingAssignmentCount": inv["selectorBearingAssignmentCount"],
            "safeDestinationCount": len(set(destinations)),
            "independentlyObservedDestinationCount": sum(
                1 for x in checks if x["independentlyObserved"]
            ),
            "simpleSelectorTernaryCount": sum(
                1 for x in inv["contexts"] if x.get("simpleSelectorTernaryRecognized")
            ),
        },
        "interpretationBoundary": {
            "wholeFileAssignmentInventory": True,
            "sameBlockPostSwitchAssumptionRemoved": True,
            "selectorValueToDestinationMappingAccepted": False,
            "safeStringsOnlyWhenBoundToNewName": True,
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
