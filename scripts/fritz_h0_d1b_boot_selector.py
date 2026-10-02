#!/usr/bin/env python3
"""Public-safe FRITZ H0-D1b boot-selector/TFFS/MTD source reduction."""
from __future__ import annotations

import argparse
import hashlib
import json
import pathlib
import re
import subprocess
import tarfile

SCHEMA_VERSION = 1
EXPERIMENT = "fritz-h0-d1b-boot-selector-topology/v1"

PREFIXES = (
    "sources/kernel/linux/arch/mips/lantiq/grx500/",
    "sources/kernel/linux/arch/mips/boot/dts/lantiq/",
    "sources/kernel/linux/drivers/char/avm_new/",
    "sources/kernel/linux/drivers/char/tffs/",
    "sources/kernel/linux/drivers/mtd/",
)

TOKENS = {
    "linux_fs_start": re.compile(rb"(?<![A-Za-z0-9_])linux_fs_start(?![A-Za-z0-9_])", re.I),
    "tffs": re.compile(rb"(?<![A-Za-z0-9_])tffs(?![A-Za-z0-9_])", re.I),
    "mtd": re.compile(rb"(?<![A-Za-z0-9_])mtd(?![A-Za-z0-9_])", re.I),
    "mtdparts": re.compile(rb"(?<![A-Za-z0-9_])mtdparts(?![A-Za-z0-9_])", re.I),
    "partition": re.compile(rb"(?<![A-Za-z0-9_])partition(?:s)?(?![A-Za-z0-9_])", re.I),
    "environment": re.compile(rb"(?<![A-Za-z0-9_])environment(?![A-Za-z0-9_])", re.I),
    "prom": re.compile(rb"(?<![A-Za-z0-9_])prom(?![A-Za-z0-9_])", re.I),
    "urlader": re.compile(rb"(?<![A-Za-z0-9_])urlader(?![A-Za-z0-9_])", re.I),
    "adam2": re.compile(rb"(?<![A-Za-z0-9_])ADAM2(?![A-Za-z0-9_])"),
    "eva": re.compile(rb"(?<![A-Za-z0-9_])EVA(?![A-Za-z0-9_])"),
    "nand": re.compile(rb"(?<![A-Za-z0-9_])nand(?![A-Za-z0-9_])", re.I),
    "grx500": re.compile(rb"(?<![A-Za-z0-9_])grx500(?![A-Za-z0-9_])", re.I),
    "grx550": re.compile(rb"(?<![A-Za-z0-9_])grx550(?![A-Za-z0-9_])", re.I),
}

MAX_FILE_BYTES = 8 * 1024 * 1024


def sha256_file(path: pathlib.Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as fp:
        for chunk in iter(lambda: fp.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def download_exact(url: str, path: pathlib.Path, expected_size: int, expected_sha256: str) -> dict:
    path.parent.mkdir(parents=True, exist_ok=True)
    cp = subprocess.run(
        ["curl","--fail","--location","--silent","--show-error","--output",str(path),url],
        capture_output=True, text=True, timeout=900
    )
    if cp.returncode:
        raise RuntimeError(f"download failed exit={cp.returncode} stderrBytes={len(cp.stderr.encode())}")
    size = path.stat().st_size
    digest = sha256_file(path)
    if size != expected_size:
        raise RuntimeError(f"size mismatch expected={expected_size} observed={size}")
    if digest.lower() != expected_sha256.lower():
        raise RuntimeError("sha256 mismatch")
    return {"bytes": size, "sha256": digest}


def normalize(name: str) -> str:
    while name.startswith("./"):
        name = name[2:]
    return name


def domain_for(path: str) -> str:
    if path.startswith("sources/kernel/linux/arch/mips/lantiq/grx500/"):
        return "grx500-boot"
    if path.startswith("sources/kernel/linux/arch/mips/boot/dts/lantiq/"):
        return "lantiq-dts"
    if path.startswith("sources/kernel/linux/drivers/char/tffs/"):
        return "tffs"
    if path.startswith("sources/kernel/linux/drivers/char/avm_new/"):
        return "avm-prom-config"
    if path.startswith("sources/kernel/linux/drivers/mtd/"):
        return "mtd"
    return "other"


def scan(archive: pathlib.Path) -> dict:
    files = []
    token_totals = {k: 0 for k in TOKENS}
    scanned = 0

    with tarfile.open(archive, "r:*") as tf:
        for m in tf:
            if not m.isfile():
                continue
            path = normalize(m.name)
            if not path.startswith(PREFIXES):
                continue
            if m.size > MAX_FILE_BYTES:
                continue
            fp = tf.extractfile(m)
            if fp is None:
                continue
            data = fp.read()
            scanned += 1
            counts = {k: len(rx.findall(data)) for k, rx in TOKENS.items()}
            present = {k:v for k,v in counts.items() if v}
            if not present:
                continue
            for k,v in present.items():
                token_totals[k] += v
            files.append({
                "path": path,
                "domain": domain_for(path),
                "size": int(m.size),
                "tokens": present,
            })

    files.sort(key=lambda x: x["path"])

    co = {}
    for item in files:
        names = sorted(item["tokens"])
        for i,a in enumerate(names):
            for b in names[i+1:]:
                key = f"{a}|{b}"
                co.setdefault(key, {"left":a,"right":b,"fileCount":0,"paths":[]})
                co[key]["fileCount"] += 1
                if len(co[key]["paths"]) < 20:
                    co[key]["paths"].append(item["path"])

    bridge = [
        x for x in files
        if "linux_fs_start" in x["tokens"] or len(x["tokens"]) >= 3
    ]

    domain_tokens = {}
    for item in files:
        d = domain_tokens.setdefault(item["domain"], {})
        for k,v in item["tokens"].items():
            d[k] = d.get(k,0) + v

    return {
        "scannedRelevantFileCount": scanned,
        "matchingFileCount": len(files),
        "files": files,
        "bridgeFiles": bridge,
        "tokenTotals": {k:v for k,v in token_totals.items() if v},
        "tokenCooccurrence": [co[k] for k in sorted(co)],
        "domainTokenTotals": {k:domain_tokens[k] for k in sorted(domain_tokens)},
    }


def run_probe(args) -> dict:
    work = pathlib.Path(args.work_dir).resolve()
    archive = work / "source-files.tar.gz"
    exact = download_exact(args.osp_url, archive, args.expected_size, args.expected_sha256)
    result = scan(archive)
    has_core = bool(result["matchingFileCount"])
    return {
        "schemaVersion": SCHEMA_VERSION,
        "experiment": EXPERIMENT,
        "classification": "H0_D1B_BOOT_SELECTOR_SOURCE_REDUCED" if has_core else "H0_D1B_NO_MATCHES",
        "oracleSatisfied": has_core,
        "sourceArtifact": {
            "provider": "AVM OSP",
            "fileName": pathlib.PurePosixPath(args.osp_url).name,
            "expectedBytes": args.expected_size,
            "expectedSha256": args.expected_sha256.lower(),
            "observedBytes": exact["bytes"],
            "observedSha256": exact["sha256"],
        },
        "reduction": result,
        "interpretationBoundary": {
            "exactPartitionLayoutAccepted": False,
            "dualBootSafetyAccepted": False,
            "linuxFsStartSemanticsAccepted": False,
            "flashDestinationAccepted": False,
            "pathTokenCooccurrenceOnly": True,
        },
        "safety": {
            "rawOspArchivePublished": False,
            "sourcePayloadPublished": False,
            "sourceSnippetsPublished": False,
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
            "error": {"type":type(exc).__name__,"message":str(exc)[:1000]},
            "safety": {
                "rawOspArchivePublished": False,
                "sourcePayloadPublished": False,
                "sourceSnippetsPublished": False,
                "physicalRouterContact": False,
                "flashWriteAuthorized": False,
                "bootEnvironmentMutationAuthorized": False,
            },
        }
        rc = 3
    receipt.write_text(json.dumps(data, indent=2, sort_keys=True)+"\n", encoding="utf-8")
    print(json.dumps({"classification":data["classification"],"oracleSatisfied":data["oracleSatisfied"]}, sort_keys=True))
    return rc


if __name__ == "__main__":
    raise SystemExit(main())
