#!/usr/bin/env python3
"""Acquire one pinned upstream Windows program; never build the reference.

Only release metadata, archive member names, executable bytes and the upstream
license are consumed. Implementation source is not opened. Python standard
library only; no free-form download URL or executable input is supported.
"""

from __future__ import annotations

import argparse
from datetime import datetime, timezone
import hashlib
import io
import json
import os
from pathlib import Path, PurePosixPath
import shutil
import stat
import sys
import tempfile
import time
import unicodedata
import urllib.parse
import urllib.request
import zipfile


VERSION = "7.5.7"
ARCHIVE_NAME = "dos2unix-7.5.7-win64.zip"
SOURCE_URL = "https://waterlander.net/dos2unix/files/" + ARCHIVE_NAME
CHECKSUM_SOURCE_URL = (
    "https://sourceforge.net/projects/dos2unix/files/dos2unix/7.5.7/"
    + ARCHIVE_NAME + "/download"
)
ARCHIVE_SHA256 = "8c1af6e366e641a859a1d58457663aedd1f3b4aae37e67621449beef145cf934"
MAX_ARCHIVE_BYTES = 16 * 1024 * 1024
MAX_EXPANDED_BYTES = 64 * 1024 * 1024
MAX_MEMBERS = 1024
MAX_LICENSE_BYTES = 256 * 1024
DOWNLOAD_DEADLINE_SECONDS = 90


def require(condition: bool, message: str) -> None:
    if not condition:
        raise ValueError(message)


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")


class OfficialRedirects(urllib.request.HTTPRedirectHandler):
    """The pinned upstream download does not need arbitrary redirect hosts."""

    def redirect_request(self, request, response, code, message, headers, new_url):
        parsed = urllib.parse.urlsplit(new_url)
        require(
            parsed.scheme == "https"
            and parsed.hostname in {"waterlander.net", "www.waterlander.net"}
            and parsed.username is None and parsed.password is None,
            "upstream redirect left the fixed official HTTPS origin",
        )
        return super().redirect_request(request, response, code, message, headers, new_url)


def download() -> tuple[bytes, str]:
    started = time.monotonic()
    request = urllib.request.Request(
        SOURCE_URL, headers={"User-Agent": "CRE-fixed-Windows-target-qualification/1"}
    )
    opener = urllib.request.build_opener(OfficialRedirects())
    with opener.open(request, timeout=20) as response:
        require(response.status == 200, "official archive request did not return HTTP 200")
        length = response.headers.get("Content-Length")
        if length is not None:
            require(0 < int(length) <= MAX_ARCHIVE_BYTES, "archive Content-Length exceeds bound")
        chunks = []
        total = 0
        while True:
            require(time.monotonic() - started <= DOWNLOAD_DEADLINE_SECONDS,
                    "official archive download deadline exceeded")
            chunk = response.read1(min(65536, MAX_ARCHIVE_BYTES - total + 1))
            require(time.monotonic() - started <= DOWNLOAD_DEADLINE_SECONDS,
                    "official archive download deadline exceeded")
            if not chunk:
                break
            total += len(chunk)
            require(total <= MAX_ARCHIVE_BYTES, "official archive exceeds byte bound")
            chunks.append(chunk)
        result = b"".join(chunks)
        require(result, "official archive is empty")
        require(sha256(result) == ARCHIVE_SHA256, "official archive SHA-256 pin mismatch")
        return result, response.geturl()


def validate_members(archive: zipfile.ZipFile) -> list[zipfile.ZipInfo]:
    """Reject path aliases and special files even though extraction is selective."""
    members = archive.infolist()
    require(0 < len(members) <= MAX_MEMBERS, "archive member count exceeds bound")
    seen = set()
    total = 0
    files = []
    for member in members:
        name = member.filename
        require(name == member.orig_filename, "archive member name was truncated during ZIP parsing")
        require(name and "\\" not in name and ":" not in name,
                "archive has an ambiguous or absolute member path")
        require(not any(ord(ch) < 32 or ord(ch) == 127 for ch in name),
                "archive member path contains control characters")
        path = PurePosixPath(name)
        require(not path.is_absolute() and ".." not in path.parts,
                "archive member traverses outside its root")
        parts = path.parts
        require(parts and all(part not in {"", ".", ".."} for part in parts),
                "archive member has no regular relative path")
        require(all(not part.endswith((" ", ".")) for part in parts),
                "archive member has a Windows path alias")
        normalized = unicodedata.normalize("NFC", "/".join(parts)).casefold()
        require(normalized not in seen, "archive contains duplicate or aliased members")
        seen.add(normalized)
        mode = member.external_attr >> 16
        kind = stat.S_IFMT(mode)
        require(kind not in {stat.S_IFLNK, stat.S_IFIFO, stat.S_IFSOCK,
                             stat.S_IFBLK, stat.S_IFCHR},
                "archive contains a symbolic link or special file")
        require(kind in {0, stat.S_IFREG, stat.S_IFDIR}, "unknown archive member type")
        require(not (member.flag_bits & 1), "encrypted archive member is unsupported")
        require(member.is_dir() == (kind == stat.S_IFDIR) or kind == 0
                or (kind == stat.S_IFREG and not member.is_dir()),
                "archive directory type and path disagree")
        require(0 <= member.file_size <= MAX_EXPANDED_BYTES, "archive member exceeds byte bound")
        total += member.file_size
        require(total <= MAX_EXPANDED_BYTES, "expanded archive exceeds byte bound")
        if not member.is_dir():
            files.append(member)
    return files


def select_payload(archive_bytes: bytes) -> tuple[bytes, bytes, str, str, int]:
    require(sha256(archive_bytes) == ARCHIVE_SHA256, "archive not verified before member use")
    with zipfile.ZipFile(io.BytesIO(archive_bytes)) as archive:
        files = validate_members(archive)
        executables = [item for item in files
                       if PurePosixPath(item.filename).name.casefold() == "dos2unix.exe"]
        licenses = [item for item in files
                    if PurePosixPath(item.filename).name.casefold() in {"copying.txt", "copying"}]
        require(len(executables) == 1, "archive must contain exactly one dos2unix.exe")
        require(len(licenses) == 1, "archive must contain exactly one unambiguous COPYING license")
        require(0 < licenses[0].file_size <= MAX_LICENSE_BYTES, "upstream license size is invalid")
        executable = archive.read(executables[0])
        license_bytes = archive.read(licenses[0])
        require(executable[:2] == b"MZ", "selected upstream executable lacks MZ signature")
        require(len(executable) == executables[0].file_size, "executable size disagrees with ZIP")
        require(len(license_bytes) == licenses[0].file_size, "license size disagrees with ZIP")
        require(license_bytes.strip(), "upstream license is empty")
        return executable, license_bytes, executables[0].filename, licenses[0].filename, len(files)


def acquire(output_dir: Path) -> dict:
    require(not output_dir.is_symlink(), "output directory must not be a symbolic link")
    output_dir.mkdir(parents=True, exist_ok=True)
    require(output_dir.is_dir(), "output path is not a directory")
    require(not (output_dir / "manifest.json").exists(), "acquisition manifest already exists")
    require(not (output_dir / "reference").exists(), "reference directory already exists")
    archive_bytes, resolved_url = download()
    executable, license_bytes, executable_member, license_member, member_count = select_payload(archive_bytes)
    manifest = {
        "schema": "cre.windows_re.acquisition.v1",
        "status": "verified",
        "target": {"name": "dos2unix", "version": VERSION,
                   "distribution": "upstream Windows 64-bit English release"},
        "source_url": SOURCE_URL,
        "resolved_source_url": resolved_url,
        "checksum_source_url": CHECKSUM_SOURCE_URL,
        "archive": {"path": "reference/" + ARCHIVE_NAME, "size_bytes": len(archive_bytes),
                    "sha256": sha256(archive_bytes), "expected_sha256": ARCHIVE_SHA256,
                    "file_member_count": member_count},
        "executable": {"path": "reference/dos2unix.exe", "archive_member": executable_member,
                       "size_bytes": len(executable), "sha256": sha256(executable)},
        "license": {"path": "reference/COPYING.txt", "archive_member": license_member,
                    "size_bytes": len(license_bytes), "sha256": sha256(license_bytes),
                    "preserved_verbatim": True},
        "provenance": {
            "acquired_at_utc": utc_now(),
            "github_sha": os.environ.get("GITHUB_SHA") or None,
            "github_run_id": os.environ.get("GITHUB_RUN_ID") or None,
            "github_run_attempt": os.environ.get("GITHUB_RUN_ATTEMPT") or None,
            "github_repository": os.environ.get("GITHUB_REPOSITORY") or None,
            "implementation_source_read": False,
            "reference_compiled_by_exercise": False,
        },
        "bounds": {"archive_bytes": MAX_ARCHIVE_BYTES, "expanded_bytes": MAX_EXPANDED_BYTES,
                   "archive_members": MAX_MEMBERS, "download_deadline_seconds": DOWNLOAD_DEADLINE_SECONDS},
    }
    staging = Path(tempfile.mkdtemp(prefix=".acquire-", dir=output_dir))
    try:
        reference = staging / "reference"
        reference.mkdir()
        (reference / "dos2unix.exe").write_bytes(executable)
        (reference / "COPYING.txt").write_bytes(license_bytes)
        (reference / ARCHIVE_NAME).write_bytes(archive_bytes)
        staged_manifest = staging / "manifest.json"
        staged_manifest.write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        # The manifest is the final commit marker. Consumers refuse incomplete packages.
        reference.replace(output_dir / "reference")
        staged_manifest.replace(output_dir / "manifest.json")
    finally:
        shutil.rmtree(staging)
    return manifest


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--outputdir", type=Path, required=True)
    args = parser.parse_args()
    try:
        manifest = acquire(args.outputdir)
    except (OSError, ValueError, zipfile.BadZipFile, RuntimeError) as error:
        print(json.dumps({"schema": "cre.windows_re.acquisition.v1", "status": "failed",
                          "error": str(error)}), file=sys.stderr)
        return 1
    print(json.dumps({"schema": manifest["schema"], "status": manifest["status"],
                      "manifest": str(args.outputdir / "manifest.json"),
                      "executable_sha256": manifest["executable"]["sha256"]}))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
