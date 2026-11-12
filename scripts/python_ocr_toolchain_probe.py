#!/usr/bin/env python3
"""Public-only, fixed synthetic Python PDF/OCR build and runtime probe.

This is generic toolchain discovery. It never accepts a user document, input
URL, source checkout, credential, script, or private clinical object.
No dependency version/apt pin, SBOM or production promotion is claimed.
"""
from __future__ import annotations

import argparse
import hashlib
import importlib.metadata
import io
import json
import os
from pathlib import Path
import platform
import re
import shutil
import subprocess
import sys
import tempfile

SCHEMA = "public-python-ocr-toolchain/v1"
EXPECTED_PYTHON = (3, 14, 10)
BASE_REF = "python@sha256:9aaa474097d094040649f2162a627c0049b408f52138d980916788d80f04802f"
FIXTURE_TEXT = "SYNTHETIC"
FIXTURE_HASH = "37e44b8d9054cf8170c30ba7adc963a485be6d25eb4bed669d8149073e665f64"
SHA256_REF = re.compile(r"^sha256:[a-f0-9]{64}$")


class Denied(ValueError):
    pass


def fixed_pdf() -> bytes:
    stream = b"BT /F1 46 Tf 72 625 Td (SYNTHETIC) Tj ET\n"
    objects = [
        b"<< /Type /Catalog /Pages 2 0 R >>",
        b"<< /Type /Pages /Count 1 /Kids [3 0 R] >>",
        b"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] /Resources << /Font << /F1 4 0 R >> >> /Contents 5 0 R >>",
        b"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>",
        b"<< /Length " + str(len(stream)).encode() + b" >>\nstream\n" + stream + b"endstream",
    ]
    data = b"%PDF-1.4\n%\xe2\xe3\xcf\xd3\n"
    offsets = [0]
    for i, body in enumerate(objects, 1):
        offsets.append(len(data))
        data += str(i).encode() + b" 0 obj\n" + body + b"\nendobj\n"
    start = len(data)
    data += b"xref\n0 6\n0000000000 65535 f \n"
    for offset in offsets[1:]:
        data += f"{offset:010} 00000 n \n".encode()
    data += b"trailer\n<< /Size 6 /Root 1 0 R >>\nstartxref\n" + str(start).encode() + b"\n%%EOF\n"
    return data


def command(args: list[str], timeout: int = 25) -> bytes:
    result = subprocess.run(args, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                            stderr=subprocess.PIPE, timeout=timeout, check=False)
    if result.returncode != 0:
        raise Denied("synthetic tool execution failed")
    return result.stdout


def inner_oracle() -> dict:
    if sys.version_info[:3] != EXPECTED_PYTHON:
        raise Denied("wrong Python interpreter patch")
    import pypdf
    import jsonschema
    raw = fixed_pdf()
    if hashlib.sha256(raw).hexdigest() != FIXTURE_HASH:
        raise Denied("fixed synthetic PDF drift")
    if FIXTURE_TEXT not in pypdf.PdfReader(io.BytesIO(raw)).pages[0].extract_text():
        raise Denied("PDF parser oracle failed")
    jsonschema.validate({"kind": "synthetic"}, {
        "type": "object", "properties": {"kind": {"const": "synthetic"}},
        "required": ["kind"], "additionalProperties": False,
    })
    with tempfile.TemporaryDirectory(prefix="public-synthetic-ocr-") as work:
        root = Path(work)
        source = root / "synthetic.pdf"
        source.write_bytes(raw)
        if FIXTURE_TEXT not in command(["pdftotext", "-layout", str(source), "-"]).decode("utf8"):
            raise Denied("Poppler text oracle failed")
        if b"Pages:           1" not in command(["pdfinfo", str(source)]):
            raise Denied("Poppler page oracle failed")
        revised = root / "rewritten.pdf"
        command(["gs", "-q", "-dNOPAUSE", "-dBATCH", "-sDEVICE=pdfwrite",
                 f"-sOutputFile={revised}", str(source)])
        if FIXTURE_TEXT not in pypdf.PdfReader(str(revised)).pages[0].extract_text():
            raise Denied("Ghostscript PDF oracle failed")
        png = root / "page.png"
        command(["pdftoppm", "-f", "1", "-l", "1", "-singlefile", "-png", "-r", "180",
                 str(source), str(png.with_suffix(""))])
        ocr = command(["tesseract", str(png), "stdout", "-l", "eng", "--psm", "6"]).decode("utf8")
        if FIXTURE_TEXT not in re.sub("[^A-Z]", "", ocr.upper()):
            raise Denied("Tesseract OCR oracle failed")
    pip_inventory = command([sys.executable, "-m", "pip", "freeze", "--all"]).decode().splitlines()
    if (not 2 <= len(pip_inventory) <= 64
            or not all(re.fullmatch(r"[A-Za-z0-9_.-]+==[A-Za-z0-9._+!:-]+", line)
                       for line in pip_inventory)):
        raise Denied("unqualified dependency inventory")
    debian_names = ("ghostscript", "poppler-utils", "tesseract-ocr", "tesseract-ocr-eng")
    debian_inventory = {
        name: command(["dpkg-query", "-W", "-f=${Version}", name]).decode().strip()
        for name in debian_names
    }
    try:
        wheel_doc = json.loads(Path("/opt/wheel-evidence.json").read_text())
    except (OSError, ValueError) as exc:
        raise Denied("candidate wheel inventory missing") from exc
    wheels = wheel_doc.get("wheels") if isinstance(wheel_doc, dict) else None
    if (wheel_doc.get("schema") != "public-python-wheel-candidate/v1"
            or wheel_doc.get("source_kind") != "fixed_public_synthetic_only"
            or not isinstance(wheels, list) or len(wheels) != 6
            or not all(isinstance(w, dict) and set(w) == {"filename", "sha256"}
                       and isinstance(w["filename"], str)
                       and re.fullmatch(r"[A-Za-z0-9_.+-]+\.whl", w["filename"])
                       and isinstance(w["sha256"], str)
                       and re.fullmatch(r"[0-9a-f]{64}", w["sha256"]) for w in wheels)
            or len({w["filename"] for w in wheels}) != len(wheels)):
        raise Denied("invalid candidate wheel identity")
    return {
        "schema": SCHEMA, "source_kind": "fixed_public_synthetic_only",
        "fixture_sha256": FIXTURE_HASH,
        "checks": ["pypdf-extraction", "jsonschema-const", "poppler-text",
                   "poppler-pages", "ghostscript-rewrite", "poppler-raster", "tesseract-ocr"],
        "python": ".".join(map(str, sys.version_info[:3])),
        "machine": platform.machine(),
        "packages": {n: importlib.metadata.version(n) for n in ("pypdf", "jsonschema")},
        "pip_inventory": pip_inventory,
        "debian_inventory": debian_inventory,
        "wheel_inventory": wheels,
        "tools": {
            "ghostscript": command(["gs", "--version"]).decode().strip(),
            "tesseract": command(["tesseract", "--version"]).decode().splitlines()[0],
            "poppler": command(["dpkg-query", "-W", "-f=${Version}", "poppler-utils"]).decode().strip(),
        },
    }


def outer_candidate(receipt_path: Path) -> dict:
    if os.environ.get("GITHUB_REPOSITORY") != "SemperSupra/agent-dispatch":
        raise Denied("public executor identity missing")
    arch = os.environ.get("RUNNER_ARCH")
    if arch not in ("X64", "ARM64") or not shutil.which("docker"):
        raise Denied("runner shape unavailable")
    machine = "x86_64" if arch == "X64" else "aarch64"
    if platform.machine() != machine or os.getuid() == 0:
        raise Denied("unqualified host privilege or architecture")
    with tempfile.TemporaryDirectory(prefix="public-ocr-build-") as temp:
        image_file = Path(temp) / "image.id"
        tag = "public-ocr-toolchain-synthetic:local"
        build_args = ["docker", "build", "--no-cache", "--pull=false",
                      "--iidfile", str(image_file), "--tag", tag,
                      "--file", "experiments/python-ocr-toolchain/Dockerfile", "."]
        try:
            build = subprocess.run(build_args, stdin=subprocess.DEVNULL, capture_output=True,
                                   text=True, timeout=190, check=False)
        except subprocess.TimeoutExpired as exc:
            raise Denied("toolchain build exceeded budget") from exc
        if build.returncode:
            raise Denied("toolchain build failed")
        image_id = image_file.read_text().strip()
        if not SHA256_REF.fullmatch(image_id):
            raise Denied("built image identity unavailable")
        execution = ["docker", "run", "--rm", "--network", "none", "--read-only",
                     "--cap-drop", "ALL", "--security-opt", "no-new-privileges",
                     "--pids-limit", "128", "--memory", "768m", "--cpus", "1",
                     "--user", "65532:65532",
                     "--tmpfs", "/tmp:rw,nosuid,nodev,size=64m",
                     image_id, "python", "/opt/probe.py", "--inner"]
        try:
            run = subprocess.run(execution, stdin=subprocess.DEVNULL, capture_output=True,
                                 text=True, timeout=40, check=False)
        except subprocess.TimeoutExpired as exc:
            raise Denied("toolchain runtime exceeded budget") from exc
        if run.returncode or len(run.stdout) > 4096:
            raise Denied("synthetic toolchain runtime failure")
        try:
            inner = json.loads(run.stdout)
        except (ValueError, UnicodeError) as exc:
            raise Denied("malformed toolchain evidence") from exc
        if (not isinstance(inner, dict)
                or inner.get("schema") != SCHEMA
                or inner.get("source_kind") != "fixed_public_synthetic_only"
                or inner.get("fixture_sha256") != FIXTURE_HASH
                or inner.get("python") != "3.14.10"
                or inner.get("machine") != machine
                or inner.get("checks") != ["pypdf-extraction", "jsonschema-const", "poppler-text",
                                          "poppler-pages", "ghostscript-rewrite", "poppler-raster",
                                          "tesseract-ocr"]):
            raise Denied("toolchain evidence mismatch")
        versions = {
            "packages": inner.get("packages"), "tools": inner.get("tools"),
            "pip_inventory": inner.get("pip_inventory"),
            "debian_inventory": inner.get("debian_inventory"),
            "wheel_inventory": inner.get("wheel_inventory"),
        }
        if (not isinstance(versions["packages"], dict)
                or set(versions["packages"]) != {"pypdf", "jsonschema"}
                or not all(isinstance(v, str) and 0 < len(v) < 128 for v in versions["packages"].values())
                or not isinstance(versions["tools"], dict)
                or set(versions["tools"]) != {"ghostscript", "tesseract", "poppler"}
                or not all(isinstance(v, str) and re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9 ._+():-]{0,127}", v)
                           for v in versions["tools"].values())
                or versions["packages"] != {"pypdf": "7.0.1", "jsonschema": "4.26.0"}
                or versions["tools"] != {"ghostscript": "10.05.1",
                                           "tesseract": "tesseract 5.5.0",
                                           "poppler": "25.03.0-5+deb13u4"}
                or not isinstance(versions["pip_inventory"], list)
                or not 2 <= len(versions["pip_inventory"]) <= 64
                or not all(isinstance(v, str) and re.fullmatch(r"[A-Za-z0-9_.-]+==[A-Za-z0-9._+!:-]+", v)
                           for v in versions["pip_inventory"])
                or not isinstance(versions["debian_inventory"], dict)
                or set(versions["debian_inventory"]) != {
                    "ghostscript", "poppler-utils", "tesseract-ocr", "tesseract-ocr-eng"}
                or not all(isinstance(v, str) and re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9.+:~_-]{0,127}", v)
                           for v in versions["debian_inventory"].values())
                or not isinstance(versions["wheel_inventory"], list)
                or len(versions["wheel_inventory"]) != 6
                or not all(isinstance(w, dict) and set(w) == {"filename", "sha256"}
                           and isinstance(w["filename"], str)
                           and re.fullmatch(r"[A-Za-z0-9_.+-]+\.whl", w["filename"])
                           and isinstance(w["sha256"], str)
                           and re.fullmatch(r"[a-f0-9]{64}", w["sha256"])
                           for w in versions["wheel_inventory"])
                or len({w["filename"] for w in versions["wheel_inventory"]}) != 6):
            raise Denied("incomplete toolchain inventory")
        version_digest = hashlib.sha256(json.dumps(versions, sort_keys=True,
                                                    separators=(",", ":")).encode()).hexdigest()
        receipt = {
            "schema": SCHEMA, "status": "CANDIDATE_SMOKE_PASS",
            "source_sha": os.environ.get("GITHUB_SHA", ""),
            "run_id": os.environ.get("GITHUB_RUN_ID", ""),
            "public_synthetic": True, "runner_arch": arch, "machine": machine,
            "base_image_ref": BASE_REF, "built_image_id": image_id,
            "toolchain_versions_sha256": version_digest,
            "toolchain_versions": versions,
            "fixture_sha256": FIXTURE_HASH, "python": "3.14.10",
            "production_promotable": False, "clinical_qualification": False,
        }
        receipt_path.parent.mkdir(parents=True, exist_ok=True)
        receipt_path.write_text(json.dumps(receipt, sort_keys=True) + "\n")
        return receipt


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--inner", action="store_true")
    parser.add_argument("--receipt", type=Path)
    args = parser.parse_args(argv)
    try:
        if args.inner:
            print(json.dumps(inner_oracle(), sort_keys=True))
        elif args.receipt:
            outer_candidate(args.receipt)
            print('{"qualification":"CANDIDATE_SMOKE_PASS"}')
        else:
            raise Denied("explicit mode required")
        return 0
    except (Denied, OSError, ValueError, UnicodeError, subprocess.TimeoutExpired):
        print('{"qualification":"NOT_QUALIFIED"}')
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
