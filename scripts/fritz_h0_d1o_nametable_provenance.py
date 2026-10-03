#!/usr/bin/env python3
"""H0-D1o: locate nametable declaration/definition provenance across exact OSP."""
from __future__ import annotations

import argparse
import importlib.util
import json
import pathlib
import re
import tarfile

_D1M_PATH = pathlib.Path(__file__).with_name("fritz_h0_d1m_nametable_binding.py")
_SPEC = importlib.util.spec_from_file_location("fritz_h0_d1m_nametable_binding", _D1M_PATH)
if _SPEC is None or _SPEC.loader is None:
    raise RuntimeError("unable to load D1m")
d1m = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(d1m)
d1h = d1m.d1h

SCHEMA_VERSION = 1
EXPERIMENT = "fritz-h0-d1o-nametable-provenance/v1"
IDENT = r"[A-Za-z_][A-Za-z0-9_]*"
TEXT_SUFFIXES = {
    ".c", ".h", ".cc", ".cpp", ".inc", ".S", ".s",
    ".dts", ".dtsi", ".mk", ".make", ".txt",
}
MAX_MEMBER_BYTES = 4 * 1024 * 1024

_DECL_RE = re.compile(
    rf"""(?x)
    \b(?P<storage>extern|static)?\s*
    (?:(?:const|volatile)\s+)*
    (?P<type>(?:struct\s+{IDENT})|{IDENT})
    \s+(?:\*+\s*)?
    nametable\b
    """
)


def normalize_member_name(name: str) -> str:
    return name[2:] if name.startswith("./") else name


def analyze_text(text: str) -> dict:
    masked = d1h.mask_comments_strings(text)
    identifier_count = len(re.findall(r"\bnametable\b", masked))
    mtd_entry_count = len(re.findall(r"\bmtd_entry\b", masked))
    declarations = []
    for m in _DECL_RE.finditer(masked):
        semi = masked.find(";", m.end(), min(len(masked), m.end() + 2048))
        if semi < 0:
            continue
        segment = masked[m.end():semi]
        eq = segment.find("=")
        initializer_brace = bool(eq >= 0 and "{" in segment[eq + 1:])
        raw_type = m.group("type")
        type_identifier = raw_type.split()[-1]
        declarations.append({
            "storageClass": m.group("storage") or "none",
            "typeClass": (
                "struct_tag" if raw_type.startswith("struct ")
                else "identifier_type"
            ),
            "typeIdentifier": type_identifier,
            "isMtdEntryType": type_identifier == "mtd_entry",
            "hasInitializer": eq >= 0,
            "hasInitializerBrace": initializer_brace,
        })
    return {
        "nametableIdentifierCount": identifier_count,
        "mtdEntryIdentifierCount": mtd_entry_count,
        "declarationCandidateCount": len(declarations),
        "externDeclarationCandidateCount": sum(
            1 for x in declarations if x["storageClass"] == "extern"
        ),
        "initializerCandidateCount": sum(
            1 for x in declarations if x["hasInitializer"]
        ),
        "bracedInitializerCandidateCount": sum(
            1 for x in declarations if x["hasInitializerBrace"]
        ),
        "mtdEntryDeclarationCandidateCount": sum(
            1 for x in declarations if x["isMtdEntryType"]
        ),
        "mtdEntryInitializerCandidateCount": sum(
            1 for x in declarations
            if x["isMtdEntryType"] and x["hasInitializer"]
        ),
        "mtdEntryBracedInitializerCandidateCount": sum(
            1 for x in declarations
            if x["isMtdEntryType"] and x["hasInitializerBrace"]
        ),
        "declarationCandidates": declarations,
    }


def scan_archive(archive: pathlib.Path) -> dict:
    hits = []
    scanned_files = 0
    skipped_oversize = 0
    with tarfile.open(archive, "r:*") as tf:
        for member in tf:
            if not member.isfile():
                continue
            path = normalize_member_name(member.name)
            if pathlib.PurePosixPath(path).suffix not in TEXT_SUFFIXES:
                continue
            if member.size > MAX_MEMBER_BYTES:
                skipped_oversize += 1
                continue
            fp = tf.extractfile(member)
            if fp is None:
                continue
            raw = fp.read()
            scanned_files += 1
            text = raw.decode("utf-8", errors="replace")
            analysis = analyze_text(text)
            if (
                analysis["nametableIdentifierCount"]
                or analysis["mtdEntryIdentifierCount"]
            ):
                hits.append({"file": path, **analysis})
    hits.sort(key=lambda x: x["file"])
    return {
        "scannedTextFileCount": scanned_files,
        "skippedOversizeTextFileCount": skipped_oversize,
        "hitFileCount": len(hits),
        "hits": hits,
    }


def classify(scan: dict) -> str:
    hits = scan.get("hits", [])
    if any(x["mtdEntryBracedInitializerCandidateCount"] for x in hits):
        return "H0_D1O_MTD_ENTRY_BRACED_DEFINITION_CANDIDATE_LOCATED"
    if any(x["mtdEntryInitializerCandidateCount"] for x in hits):
        return "H0_D1O_MTD_ENTRY_DEFINITION_CANDIDATE_LOCATED"
    if any(x["mtdEntryDeclarationCandidateCount"] for x in hits):
        return "H0_D1O_MTD_ENTRY_DECLARATION_CANDIDATE_LOCATED"
    if any(x["nametableIdentifierCount"] for x in hits):
        return "H0_D1O_NAMETABLE_USES_OR_UNRELATED_DECLARATIONS_ONLY"
    return "H0_D1O_NAMETABLE_NOT_FOUND"


def run_probe(args):
    work = pathlib.Path(args.work_dir).resolve()
    work.mkdir(parents=True, exist_ok=True)
    archive = work / "source-files.tar.gz"
    exact = d1h.download_exact(
        args.osp_url, archive, args.expected_size, args.expected_sha256
    )
    scan = scan_archive(archive)
    classification = classify(scan)
    return {
        "schemaVersion": SCHEMA_VERSION,
        "experiment": EXPERIMENT,
        "classification": classification,
        "oracleSatisfied": True,
        "sourceArtifact": {
            "expectedBytes": args.expected_size,
            "expectedSha256": args.expected_sha256.lower(),
            "observedBytes": exact["bytes"],
            "observedSha256": exact["sha256"],
        },
        "corpusScan": scan,
        "derived": {
            "declarationCandidateFileCount": sum(
                1 for x in scan["hits"] if x["declarationCandidateCount"]
            ),
            "initializerCandidateFileCount": sum(
                1 for x in scan["hits"] if x["initializerCandidateCount"]
            ),
            "bracedInitializerCandidateFileCount": sum(
                1 for x in scan["hits"] if x["bracedInitializerCandidateCount"]
            ),
            "mtdEntryDeclarationCandidateFileCount": sum(
                1 for x in scan["hits"]
                if x["mtdEntryDeclarationCandidateCount"]
            ),
            "mtdEntryInitializerCandidateFileCount": sum(
                1 for x in scan["hits"]
                if x["mtdEntryInitializerCandidateCount"]
            ),
            "mtdEntryBracedInitializerCandidateFileCount": sum(
                1 for x in scan["hits"]
                if x["mtdEntryBracedInitializerCandidateCount"]
            ),
        },
        "interpretationBoundary": {
            "pathsAndIdentifierCountsOnly": True,
            "declarationShapeIsCandidateEvidenceOnly": True,
            "sourceSnippetsAccepted": False,
            "arbitraryStringLiteralsAccepted": False,
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
        rc = 0
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
        "corpusScan": data.get("corpusScan", {}),
    }, sort_keys=True))
    return rc


if __name__ == "__main__":
    raise SystemExit(main())
