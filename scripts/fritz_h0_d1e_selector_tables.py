#!/usr/bin/env python3
"""Public-safe H0-D1e global table schema reduction for linux_fs_start."""
from __future__ import annotations

import argparse
import hashlib
import json
import pathlib
import re
import subprocess
import tarfile

SCHEMA_VERSION = 1
EXPERIMENT = "fritz-h0-d1e-selector-table-schema/v1"
KEY = "linux_fs_start"
FILES = (
    "sources/kernel/linux/drivers/mtd/avm/avm_mtd.c",
    "sources/kernel/linux/drivers/char/tffs/include/uapi/avm/tffs/tffs.h",
    "sources/kernel/linux/drivers/char/tffs/env.c",
)

IDENT_RE = re.compile(r"\b[A-Za-z_][A-Za-z0-9_]*\b")
DESIGNATOR_RE = re.compile(r"\.([A-Za-z_][A-Za-z0-9_]*)\s*=")
DECL_RE = re.compile(
    r"(?s)(?:^|[;}]\s*)"
    r"(?P<decl>(?:static\s+|const\s+|volatile\s+|__\w+\s+)*"
    r"(?:struct\s+[A-Za-z_][A-Za-z0-9_]*|enum\s+[A-Za-z_][A-Za-z0-9_]*|"
    r"[A-Za-z_][A-Za-z0-9_]*(?:\s+[*A-Za-z_][A-Za-z0-9_]*)*)"
    r"\s+(?P<owner>[A-Za-z_][A-Za-z0-9_]*)\s*(?:\[[^]]*\])?\s*=\s*)$"
)
C_KEYWORDS = {
    "auto","break","case","char","const","continue","default","do","double","else",
    "enum","extern","float","for","goto","if","inline","int","long","register",
    "restrict","return","short","signed","sizeof","static","struct","switch",
    "typedef","union","unsigned","void","volatile","while","true","false","NULL",
}
GENERIC_NOISE = {
    KEY, "linux", "fs", "start",
}
CALLBACK_HINTS = (
    "get","set","read","write","parse","find","select","handler","callback","cb",
    "init","lookup","env","prom","tffs","mtd","rootfs","partition",
)


def sha256_file(path: pathlib.Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as fp:
        for chunk in iter(lambda: fp.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def download_exact(url: str, path: pathlib.Path, size: int, digest: str) -> dict:
    path.parent.mkdir(parents=True, exist_ok=True)
    cp = subprocess.run(
        ["curl","--fail","--location","--silent","--show-error","--output",str(path),url],
        capture_output=True, text=True, timeout=900,
    )
    if cp.returncode:
        raise RuntimeError(f"download failed exit={cp.returncode}")
    if path.stat().st_size != size:
        raise RuntimeError("size mismatch")
    got = sha256_file(path)
    if got.lower() != digest.lower():
        raise RuntimeError("sha256 mismatch")
    return {"bytes": path.stat().st_size, "sha256": got}


def extract_selected(archive: pathlib.Path) -> dict[str, str]:
    wanted = set(FILES)
    out: dict[str, str] = {}
    with tarfile.open(archive, "r:*") as tf:
        for m in tf:
            name = m.name[2:] if m.name.startswith("./") else m.name
            if name not in wanted or not m.isfile():
                continue
            fp = tf.extractfile(m)
            if fp is not None:
                out[name] = fp.read().decode("utf-8", errors="replace")
    return out


def mask_comments_and_strings(text: str) -> str:
    out = list(text)
    i = 0
    quote = None
    while i < len(out):
        ch = out[i]
        if quote:
            if ch == "\\":
                out[i] = " "
                if i + 1 < len(out):
                    out[i + 1] = " "
                    i += 2
                    continue
            if ch == quote:
                quote = None
            out[i] = " "
            i += 1
            continue
        if ch in ("'", '"'):
            quote = ch
            out[i] = " "
            i += 1
            continue
        if ch == "/" and i + 1 < len(out) and out[i + 1] == "*":
            out[i] = out[i + 1] = " "
            i += 2
            while i + 1 < len(out) and not (out[i] == "*" and out[i + 1] == "/"):
                if out[i] != "\n":
                    out[i] = " "
                i += 1
            if i + 1 < len(out):
                out[i] = out[i + 1] = " "
                i += 2
            continue
        if ch == "/" and i + 1 < len(out) and out[i + 1] == "/":
            out[i] = out[i + 1] = " "
            i += 2
            while i < len(out) and out[i] != "\n":
                out[i] = " "
                i += 1
            continue
        i += 1
    return "".join(out)


def brace_pairs(masked: str) -> dict[int, int]:
    stack: list[int] = []
    pairs: dict[int, int] = {}
    for i, ch in enumerate(masked):
        if ch == "{":
            stack.append(i)
        elif ch == "}" and stack:
            start = stack.pop()
            pairs[start] = i
    return pairs


def enclosing_braces(masked: str, pos: int) -> list[tuple[int, int]]:
    pairs = brace_pairs(masked)
    return sorted(
        [(a, b) for a, b in pairs.items() if a < pos < b],
        key=lambda x: (x[1] - x[0]),
    )


def declaration_before(masked: str, brace_start: int) -> dict | None:
    prefix = masked[max(0, brace_start - 1200):brace_start]
    m = DECL_RE.search(prefix)
    if not m:
        return None
    decl = " ".join(m.group("decl").split())
    owner = m.group("owner")
    type_ids = [
        x for x in IDENT_RE.findall(decl)
        if x not in C_KEYWORDS and x != owner
    ]
    return {
        "owner": owner,
        "typeIdentifiers": sorted(set(type_ids)),
    }


def entry_span(masked: str, key_pos: int, outer_start: int, outer_end: int) -> tuple[int, int]:
    depth = 0
    start = outer_start + 1
    i = outer_start + 1
    while i < key_pos:
        ch = masked[i]
        if ch == "{":
            depth += 1
            if depth == 1:
                start = i
        elif ch == "}":
            if depth == 1:
                start = i + 1
            depth = max(0, depth - 1)
        elif ch == "," and depth == 0:
            start = i + 1
        i += 1

    depth = 0
    end = outer_end
    i = key_pos
    while i < outer_end:
        ch = masked[i]
        if ch == "{":
            depth += 1
        elif ch == "}":
            if depth == 0:
                end = i
                break
            depth -= 1
        elif ch == "," and depth == 0:
            end = i
            break
        i += 1
    return start, end


def safe_identifiers(fragment: str) -> dict:
    masked = mask_comments_and_strings(fragment)
    designators = sorted(set(DESIGNATOR_RE.findall(masked)))
    ids = sorted(set(
        x for x in IDENT_RE.findall(masked)
        if x not in C_KEYWORDS and x not in GENERIC_NOISE
    ))
    enum_like = [x for x in ids if re.fullmatch(r"[A-Z][A-Z0-9_]{2,}", x)]
    callback_like = [
        x for x in ids
        if any(h in x.lower() for h in CALLBACK_HINTS)
        and x not in designators
    ]
    return {
        "designatedFields": designators,
        "identifierReferences": ids,
        "enumLikeReferences": enum_like,
        "callbackLikeReferences": callback_like,
    }


def reduce_file(path: str, text: str) -> list[dict]:
    # Locate key in original text so quoted-key entries remain discoverable.
    positions = [m.start() for m in re.finditer(r"\blinux_fs_start\b", text)]
    masked = mask_comments_and_strings(text)
    results = []
    for ordinal, pos in enumerate(positions, start=1):
        enclosers = enclosing_braces(masked, pos)
        owner = None
        owner_span = None
        for start, end in enclosers:
            decl = declaration_before(masked, start)
            if decl:
                owner = decl
                owner_span = (start, end)
                break

        if owner_span:
            es, ee = entry_span(masked, pos, owner_span[0], owner_span[1])
            fragment = text[es:ee]
            schema = safe_identifiers(fragment)
        else:
            schema = {
                "designatedFields": [],
                "identifierReferences": [],
                "enumLikeReferences": [],
                "callbackLikeReferences": [],
            }

        line_ordinal = text.count("\n", 0, pos) + 1
        results.append({
            "file": path,
            "occurrenceOrdinal": ordinal,
            "lineOrdinal": line_ordinal,
            "owner": owner,
            "entrySchema": schema,
            "ownerResolved": owner is not None,
        })
    return results


def reduce(selected: dict[str, str]) -> dict:
    occurrences = []
    for path, text in sorted(selected.items()):
        occurrences.extend(reduce_file(path, text))

    owners: dict[str, dict] = {}
    for item in occurrences:
        owner = item.get("owner")
        if not owner:
            continue
        key = f'{item["file"]}:{owner["owner"]}'
        rec = owners.setdefault(key, {
            "file": item["file"],
            "owner": owner["owner"],
            "typeIdentifiers": owner["typeIdentifiers"],
            "occurrenceCount": 0,
            "designatedFields": set(),
            "identifierReferences": set(),
            "enumLikeReferences": set(),
            "callbackLikeReferences": set(),
        })
        rec["occurrenceCount"] += 1
        for field in ("designatedFields","identifierReferences","enumLikeReferences","callbackLikeReferences"):
            rec[field].update(item["entrySchema"][field])

    owner_list = []
    for key in sorted(owners):
        rec = owners[key]
        for field in ("designatedFields","identifierReferences","enumLikeReferences","callbackLikeReferences"):
            rec[field] = sorted(rec[field])
        owner_list.append(rec)

    return {
        "occurrences": occurrences,
        "owners": owner_list,
        "derived": {
            "occurrenceCount": len(occurrences),
            "resolvedOwnerCount": len(owner_list),
            "resolvedOccurrenceCount": sum(1 for x in occurrences if x["ownerResolved"]),
        },
    }


def run_probe(args) -> dict:
    work = pathlib.Path(args.work_dir).resolve()
    work.mkdir(parents=True, exist_ok=True)
    archive = work / "source-files.tar.gz"
    exact = download_exact(args.osp_url, archive, args.expected_size, args.expected_sha256)
    selected = extract_selected(archive)
    missing = sorted(set(FILES) - set(selected))
    schema = reduce(selected)
    return {
        "schemaVersion": SCHEMA_VERSION,
        "experiment": EXPERIMENT,
        "classification": "H0_D1E_SELECTOR_TABLE_SCHEMA_RECOVERED" if not missing else "H0_D1E_SOURCE_MISSING",
        "oracleSatisfied": not missing and schema["derived"]["occurrenceCount"] > 0,
        "sourceArtifact": {
            "expectedBytes": args.expected_size,
            "expectedSha256": args.expected_sha256.lower(),
            "observedBytes": exact["bytes"],
            "observedSha256": exact["sha256"],
        },
        "missingFiles": missing,
        "schema": schema,
        "interpretationBoundary": {
            "tableOwnershipRecovered": schema["derived"]["resolvedOwnerCount"] > 0,
            "numericValuesPublished": False,
            "stringValuesPublished": False,
            "exactValueToSlotMappingAccepted": False,
            "exactPartitionLayoutAccepted": False,
            "dualBootSafetyAccepted": False,
        },
        "safety": {
            "rawOspArchivePublished": False,
            "sourcePayloadPublished": False,
            "sourceSnippetsPublished": False,
            "arbitraryStringLiteralsPublished": False,
            "numericOffsetsPublished": False,
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
    rp = pathlib.Path(args.receipt)
    rp.parent.mkdir(parents=True, exist_ok=True)
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
                "numericOffsetsPublished": False,
                "physicalRouterContact": False,
                "flashWriteAuthorized": False,
                "bootEnvironmentMutationAuthorized": False,
            },
        }
        rc = 3
    rp.write_text(json.dumps(data, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps({"classification": data["classification"], "oracleSatisfied": data["oracleSatisfied"]}, sort_keys=True))
    return rc


if __name__ == "__main__":
    raise SystemExit(main())
