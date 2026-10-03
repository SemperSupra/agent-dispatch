#!/usr/bin/env python3
"""H0-D1i: recover post-switch linux_fs_start -> destination mapping.

D1h proved that the exact source normalizes linux_fs_start to {0,1}, while the
destination assignment occurs downstream of the switch. D1i examines only the
post-switch region in the same enclosing block and only assignments to the
already observed destination identifier new_name. Simple selector ternaries are
normalized into selector-value -> safe destination facts and cross-checked
against independently selected AVM partition/device-tree sources.

No source lines, snippets, arbitrary literals, offsets, or writable HIL actions
are emitted.
"""
from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import pathlib
import re

_D1H_PATH = pathlib.Path(__file__).with_name("fritz_h0_d1h_selector_switch.py")
_SPEC = importlib.util.spec_from_file_location("fritz_h0_d1h_selector_switch", _D1H_PATH)
if _SPEC is None or _SPEC.loader is None:
    raise RuntimeError("unable to load D1h")
d1h = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(d1h)

SCHEMA_VERSION = 1
EXPERIMENT = "fritz-h0-d1i-selector-destination/v2"
SELECTOR = "linux_fs_start"
DEST_LHS = "new_name"
FILES = d1h.FILES
SAFE_DEST_RE = d1h.SAFE_DEST_RE

_SWITCH_RE = re.compile(r"\bswitch\s*\(\s*linux_fs_start\s*\)\s*\{")
_ASSIGN_RE = re.compile(
    r"\bnew_name\s*=\s*(?P<rhs>[^;\n]*\blinux_fs_start\b[^;\n]*)\s*;"
)
_TERNARY_RE = re.compile(
    r"^\s*(?P<cond>.+?)\s*\?\s*(?P<t>.+?)\s*:\s*(?P<f>.+?)\s*$",
    re.S,
)
_QUOTED_RE = re.compile(r"^\s*[\"'](?P<value>[^\"']+)[\"']\s*$")


def _strip_outer_parens(value: str) -> str:
    s = value.strip()
    changed = True
    while changed and len(s) >= 2 and s[0] == "(" and s[-1] == ")":
        depth = 0
        changed = False
        balanced = True
        for i, ch in enumerate(s):
            if ch == "(":
                depth += 1
            elif ch == ")":
                depth -= 1
                if depth == 0 and i != len(s) - 1:
                    balanced = False
                    break
        if balanced and depth == 0:
            s = s[1:-1].strip()
            changed = True
    return s


def normalize_condition(cond: str) -> dict[int, bool] | None:
    c = re.sub(r"\s+", "", _strip_outer_parens(cond))
    forms = {
        SELECTOR: {0: False, 1: True},
        f"!{SELECTOR}": {0: True, 1: False},
        f"{SELECTOR}==0": {0: True, 1: False},
        f"0=={SELECTOR}": {0: True, 1: False},
        f"{SELECTOR}==1": {0: False, 1: True},
        f"1=={SELECTOR}": {0: False, 1: True},
        f"{SELECTOR}!=0": {0: False, 1: True},
        f"0!={SELECTOR}": {0: False, 1: True},
        f"{SELECTOR}!=1": {0: True, 1: False},
        f"1!={SELECTOR}": {0: True, 1: False},
    }
    return forms.get(c)


def safe_quoted_destination(expr: str) -> str | None:
    m = _QUOTED_RE.fullmatch(expr)
    if not m:
        return None
    value = m.group("value")
    return value if SAFE_DEST_RE.fullmatch(value) else None


def ternary_mapping(rhs: str) -> dict[str, str] | None:
    m = _TERNARY_RE.fullmatch(rhs)
    if not m:
        return None
    truth = normalize_condition(m.group("cond"))
    if truth is None:
        return None
    true_dest = safe_quoted_destination(m.group("t"))
    false_dest = safe_quoted_destination(m.group("f"))
    if true_dest is None or false_dest is None:
        return None
    return {
        str(value): true_dest if predicate_true else false_dest
        for value, predicate_true in sorted(truth.items())
    }


def post_switch_region(text: str) -> dict:
    masked = d1h.mask_comments_strings(text)
    sm = _SWITCH_RE.search(masked)
    if not sm:
        return {"switchFound": False, "switchClosed": False, "region": ""}

    open_idx = masked.find("{", sm.start(), sm.end())
    close_idx = d1h.match_brace(text, open_idx)
    if close_idx is None:
        return {"switchFound": True, "switchClosed": False, "region": ""}

    # Determine lexical depth after the switch closes. Scan forward until that
    # enclosing block closes; this is bounded and avoids a brittle function-
    # header parser.
    depth = 0
    for ch in masked[: close_idx + 1]:
        if ch == "{":
            depth += 1
        elif ch == "}":
            depth -= 1
    base_depth = depth

    end = len(text)
    local_depth = base_depth
    for i in range(close_idx + 1, len(masked)):
        ch = masked[i]
        if ch == "{":
            local_depth += 1
        elif ch == "}":
            local_depth -= 1
            if local_depth < base_depth:
                end = i
                break

    return {
        "switchFound": True,
        "switchClosed": True,
        "region": text[close_idx + 1 : end],
    }


def reduce_post_switch_mapping(text: str) -> dict:
    region_info = post_switch_region(text)
    if not region_info["switchFound"] or not region_info["switchClosed"]:
        return {
            "switchFound": region_info["switchFound"],
            "switchClosed": region_info["switchClosed"],
            "candidateAssignmentCount": 0,
            "normalizedMappings": [],
        }

    region = region_info["region"]
    mappings = []
    candidates = 0
    candidate_shapes: dict[str, int] = {}

    for m in _ASSIGN_RE.finditer(region):
        candidates += 1
        rhs = m.group("rhs").strip()
        shape = "ternary" if ("?" in rhs and ":" in rhs) else "non_ternary"
        candidate_shapes[shape] = candidate_shapes.get(shape, 0) + 1
        mapping = ternary_mapping(rhs)
        if mapping is None:
            continue
        mappings.append({
            "lhs": DEST_LHS,
            "selectorDomain": [0, 1],
            "caseMapping": mapping,
            "rhsSha256": hashlib.sha256(rhs.encode()).hexdigest(),
        })

    return {
        "switchFound": True,
        "switchClosed": True,
        "candidateAssignmentCount": candidates,
        "candidateShapeCounts": dict(sorted(candidate_shapes.items())),
        "normalizedMappings": mappings,
    }


def crosscheck(destinations: list[str], selected: dict[str, str]) -> list[dict]:
    out = []
    for dest in sorted(set(destinations)):
        per_file = []
        for path, text in sorted(selected.items()):
            if path.endswith("avm_mtd.c"):
                continue
            count = len(re.findall(
                rf"(?<![A-Za-z0-9_.+-]){re.escape(dest)}(?![A-Za-z0-9_.+-])",
                text,
            ))
            if count:
                per_file.append({"file": path, "count": count})
        out.append({
            "destination": dest,
            "independentMatches": per_file,
            "independentlyObserved": bool(per_file),
        })
    return out


def classify(reduction: dict, checks: list[dict], missing: list[str]) -> str:
    if missing:
        return "H0_D1I_SOURCE_MISSING"
    mappings = reduction.get("normalizedMappings", [])
    if mappings:
        mapped_destinations = {
            dest
            for mapping in mappings
            for dest in mapping["caseMapping"].values()
        }
        checked_destinations = {x["destination"] for x in checks}
        fully_crosschecked = (
            bool(mapped_destinations)
            and checked_destinations == mapped_destinations
            and all(x["independentlyObserved"] for x in checks)
        )
        if fully_crosschecked:
            return "H0_D1I_SELECTOR_DESTINATION_MAPPING_CROSSCHECKED"
        return "H0_D1I_SELECTOR_DESTINATION_MAPPING_CROSSCHECK_PARTIAL"
    if reduction.get("candidateAssignmentCount", 0):
        return "H0_D1I_SELECTOR_DESTINATION_ASSIGNMENT_PARTIAL"
    if reduction.get("switchFound") and reduction.get("switchClosed"):
        return "H0_D1I_POST_SWITCH_DESTINATION_ASSIGNMENT_NOT_FOUND"
    return "H0_D1I_SELECTOR_SWITCH_CONTEXT_PARTIAL"


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
    reduction = reduce_post_switch_mapping(selected.get(avm_path, ""))

    destinations = [
        dest
        for mapping in reduction.get("normalizedMappings", [])
        for dest in mapping["caseMapping"].values()
    ]
    checks = crosscheck(destinations, selected)
    classification = classify(reduction, checks, missing)
    oracle = not missing

    return {
        "schemaVersion": SCHEMA_VERSION,
        "experiment": EXPERIMENT,
        "classification": classification,
        "oracleSatisfied": oracle,
        "sourceArtifact": {
            "expectedBytes": args.expected_size,
            "expectedSha256": args.expected_sha256.lower(),
            "observedBytes": exact["bytes"],
            "observedSha256": exact["sha256"],
        },
        "missingFiles": missing,
        "postSwitchReduction": reduction,
        "destinationCrosscheck": checks,
        "derived": {
            "normalizedMappingCount": len(reduction.get("normalizedMappings", [])),
            "destinationCount": len(set(destinations)),
            "independentlyObservedDestinationCount": sum(
                1 for x in checks if x["independentlyObserved"]
            ),
            "mappingFullyCrosschecked": bool(checks)
            and all(x["independentlyObserved"] for x in checks),
        },
        "interpretationBoundary": {
            "selectorDomainAcceptedFromD1h": [0, 1],
            "postSwitchSameEnclosingBlockOnly": True,
            "destinationLhsRestrictedToNewName": True,
            "normalizedTernaryMappingIsDerivedSourceFact": bool(
                reduction.get("normalizedMappings", [])
            ),
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
