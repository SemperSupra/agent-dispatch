#!/usr/bin/env python3
"""Public-only artifact source-identity audit. No private Winnow or Instagram.

The comparison is observational: source file hash equivalence is not a build
attestation, upstream signature verification, authorization, or source proof.
"""
import hashlib
import io
import json
from pathlib import Path
import sys
import tarfile
import urllib.error
import urllib.request
import zipfile

NAME = "gallery-dl"
VERSION = "1.32.19"
WHEEL_SHA = "f6b1eb5e9a7409a988b754335d99dbb1873e130d133ed5d164d32e5e645d1c50"
TARGET = "gallery_dl/extractor/instagram.py"
MAX_SOURCE = 2 << 20
MAX_DOWNLOAD = 20 << 20
URLS = {
    "pypi_metadata": "https://pypi.org/pypi/gallery-dl/1.32.19/json",
    "github_signed_tag_mirror_raw":
        "https://raw.githubusercontent.com/mikf/gallery-dl/v1.32.19/gallery_dl/extractor/instagram.py",
    "codeberg_primary_tag_raw":
        "https://codeberg.org/mikf/gallery-dl/raw/tag/v1.32.19/gallery_dl/extractor/instagram.py",
}


def fetch(url, max_bytes=MAX_DOWNLOAD):
    req = urllib.request.Request(url, headers={"User-Agent": "WinnowPublicR42ArtifactAudit/1.0"})
    with urllib.request.urlopen(req, timeout=20) as resp:
        if not resp.url.startswith("https://"):
            raise RuntimeError("R42_REDIRECT_TO_INSECURE_ORIGIN")
        data = resp.read(max_bytes + 1)
    if not data or len(data) > max_bytes:
        raise RuntimeError("R42_DOWNLOAD_SIZE_INVALID")
    return data


def hash_bytes(data):
    return hashlib.sha256(data).hexdigest()


def find_target_archive(blob, archive_type):
    if archive_type == "bdist_wheel":
        with zipfile.ZipFile(io.BytesIO(blob)) as zipped:
            candidates = [m for m in zipped.infolist() if
                          m.filename == TARGET and not m.is_dir()]
            if len(candidates) != 1 or candidates[0].file_size > MAX_SOURCE:
                raise RuntimeError("R42_WHEEL_TARGET_MISSING_DUPLICATE_OR_OVERSIZE")
            content = zipped.read(candidates[0])
    elif archive_type == "sdist":
        with tarfile.open(fileobj=io.BytesIO(blob), mode="r:gz") as tar:
            candidates = [m for m in tar.getmembers() if
                          (m.name == TARGET or m.name.endswith("/" + TARGET))
                          and m.isfile()]
            if len(candidates) != 1 or candidates[0].size > MAX_SOURCE:
                raise RuntimeError("R42_SDIST_TARGET_MISSING_DUPLICATE_OR_OVERSIZE")
            f = tar.extractfile(candidates[0])
            if f is None:
                raise RuntimeError("R42_SDIST_EXTRACT_REJECTED")
            content = f.read(MAX_SOURCE + 1)
    else:
        raise RuntimeError("R42_UNKNOWN_ARCHIVE_TYPE")
    if len(content) > MAX_SOURCE or b"class InstagramExtractor" not in content:
        raise RuntimeError("R42_SOURCE_FILE_SHAPE_INVALID")
    return content


def summary_of_source(data):
    return {
        "sha256": hash_bytes(data),
        "bytes": len(data),
        "has_parse_post_rest": b"def _parse_post_rest(" in data,
        "has_parse_post": b"def _parse_post(" in data,
        "source_code_shape_checked": True,
    }


def main():
    if len(sys.argv) != 2:
        raise RuntimeError("usage: audit.py result.json")
    out = Path(sys.argv[1])
    meta = json.loads(fetch(URLS["pypi_metadata"], 4 << 20))
    if meta.get("info", {}).get("version") != VERSION:
        raise RuntimeError("R42_PYPI_METADATA_VERSION_DRIFT")
    files = meta.get("urls") or []
    downloads = {}
    for kind in ("bdist_wheel", "sdist"):
        entries = [f for f in files if f.get("packagetype") == kind]
        if len(entries) != 1:
            raise RuntimeError("R42_PYPI_MULTIPLE_OR_MISSING_ARTIFACTS_" + kind)
        entry = entries[0]
        if not entry.get("url", "").startswith("https://files.pythonhosted.org/"):
            raise RuntimeError("R42_UNEXPECTED_DISTRIBUTION_ORIGIN")
        content = fetch(entry["url"])
        observed_hash = hash_bytes(content)
        if observed_hash != entry.get("digests", {}).get("sha256"):
            raise RuntimeError("R42_DISTRIBUTION_DIGEST_INVALID_" + kind)
        if kind == "bdist_wheel" and observed_hash != WHEEL_SHA:
            raise RuntimeError("R42_PINNED_WHEEL_HASH_DRIFT")
        source = find_target_archive(content, kind)
        downloads[kind] = {
            "artifact_filename": entry.get("filename"),
            "artifact_sha256": observed_hash,
            "source": summary_of_source(source),
        }

    github_source = fetch(URLS["github_signed_tag_mirror_raw"], MAX_SOURCE)
    if b"class InstagramExtractor" not in github_source:
        raise RuntimeError("R42_GITHUB_TAG_SOURCE_SHAPE_INVALID")
    remote = {"github_tag_mirror": summary_of_source(github_source)}
    # Codeberg is the declared primary upstream. Fetch is best-effort because
    # some hosts refuse public GHA proxies; inability is a separate HOLD, not
    # proof of absence or equivalence.
    try:
        primary = fetch(URLS["codeberg_primary_tag_raw"], MAX_SOURCE)
        if b"class InstagramExtractor" not in primary:
            raise RuntimeError("R42_CODEBERG_NOT_SOURCE_TEXT")
        remote["codeberg_primary_tag"] = summary_of_source(primary)
        remote["codeberg_fetch_status"] = "SOURCE_BYTES_OBSERVED"
    except (urllib.error.URLError, TimeoutError, RuntimeError) as exc:
        remote["codeberg_fetch_status"] = "FETCH_OR_SHAPE_UNVERIFIED"
        remote["codeberg_error_type"] = type(exc).__name__

    w = downloads["bdist_wheel"]["source"]["sha256"]
    s = downloads["sdist"]["source"]["sha256"]
    g = remote["github_tag_mirror"]["sha256"]
    report = {
        "schema_version": 1,
        "scope": "PUBLIC_GALLERY_DL_DISTRIBUTION_SOURCE_FILE_AUDIT_ONLY",
        "version": VERSION,
        "artifacts": downloads,
        "remote_sources": remote,
        "compare": {
            "wheel_matches_sdist_file_bytes": w == s,
            "wheel_matches_github_tag_file_bytes": w == g,
            "sdist_matches_github_tag_file_bytes": s == g,
            "codeberg_file_comparison": (
                "NOT_VERIFIED" if "codeberg_primary_tag" not in remote else
                ("MATCHES_WHEEL" if remote["codeberg_primary_tag"]["sha256"] == w else "DIFFERS_WHEEL")
            ),
        },
        "no_real_instagram_requests": True,
        "no_private_winnow_code": True,
        "no_signed_source_tag_verified": True,
        "no_reproducible_wheel_build_proven": True,
        "release_qualified": False,
    }
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n")
    print(json.dumps(report, sort_keys=True), flush=True)
    print("R42_PUBLIC_WHEEL_SDIST_GITHUB_BYTES_COMPARED source_attestation=NOT_VERIFIED release=HOLD")


if __name__ == "__main__":
    main()
