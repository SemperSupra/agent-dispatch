#!/usr/bin/env python3
"""Public-only, bounded pinned gallery-dl packaging/CLI contract probe.

Source: PyPI 1.32.19, exact reviewed wheel SHA-256. NEVER contacts Instagram,
uses cookies, emits user/private data, or exercises live media acquisition.
"""
from __future__ import annotations

import hashlib
import io
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
from urllib.parse import urlparse
from urllib.request import urlopen
import zipfile

VERSION = "1.32.19"
WHEEL = "gallery_dl-1.32.19-py3-none-any.whl"
SHA256 = "f6b1eb5e9a7409a988b754335d99dbb1873e130d133ed5d164d32e5e645d1c50"
MAX_WHEEL_BYTES = 2_500_000
MAX_INFLATED = 20_000_000

def bounded_get(url: str, max_bytes: int) -> bytes:
    parsed = urlparse(url)
    if parsed.scheme != "https" or parsed.hostname not in ("pypi.org", "files.pythonhosted.org"):
        raise RuntimeError("PUBLIC_PACKAGE_SOURCE_DENIED")
    with urlopen(url, timeout=12) as response:
        if response.status != 200:
            raise RuntimeError("PACKAGE_SOURCE_NOT_OK")
        data = response.read(max_bytes + 1)
    if not data or len(data) > max_bytes:
        raise RuntimeError("PACKAGE_BYTES_OUT_OF_BOUNDS")
    return data

def run():
    meta = json.loads(bounded_get("https://pypi.org/pypi/gallery-dl/" + VERSION + "/json", 300_000))
    distributions = [x for x in meta["urls"] if x.get("filename") == WHEEL]
    if len(distributions) != 1:
        raise RuntimeError("PINNED_WHEEL_NOT_FOUND")
    dist = distributions[0]
    if dist.get("digests", {}).get("sha256") != SHA256:
        raise RuntimeError("PYPI_METADATA_HASH_CHANGED")
    wheel_url = dist["url"]
    if urlparse(wheel_url).hostname != "files.pythonhosted.org":
        raise RuntimeError("UNEXPECTED_PACKAGE_ORIGIN")
    wheel = bounded_get(wheel_url, MAX_WHEEL_BYTES)
    if hashlib.sha256(wheel).hexdigest() != SHA256:
        raise RuntimeError("DOWNLOADED_WHEEL_DIGEST_MISMATCH")
    with zipfile.ZipFile(io.BytesIO(wheel)) as z:
        names = z.namelist()
        if len(names) > 500 or sum(x.file_size for x in z.infolist()) > MAX_INFLATED:
            raise RuntimeError("PACKAGE_ARCHIVE_TOO_LARGE")
        if any(n.startswith("/") or ".." in Path(n).parts for n in names):
            raise RuntimeError("PACKAGE_UNSAFE_PATH")
        instagram = [n for n in names if n == "gallery_dl/extractor/instagram.py"]
        metadata = [n for n in names if n.endswith(".dist-info/METADATA")]
        options = [n for n in names if n == "gallery_dl/option.py"]
        if len(instagram) != 1 or len(metadata) != 1 or len(options) != 1:
            raise RuntimeError("EXPECTED_EXTRACTOR_CLI_SOURCE_MISSING")
        pkgmeta = z.read(metadata[0]).decode("utf-8", "replace")
        if "Version: "+VERSION not in pkgmeta:
            raise RuntimeError("VERSION_METADATA_MISMATCH")
        option_src = z.read(options[0])
        for flag in (b"--get-urls", b"--range", b"--config-ignore", b"--filesize-max", b"--no-input"):
            if flag not in option_src:
                raise RuntimeError("CLI_FLAG_ABSENT_IN_PINNED_WHEEL")
        instagram_sha256 = hashlib.sha256(z.read(instagram[0])).hexdigest()
    with tempfile.TemporaryDirectory(prefix="public-gallerydl-") as td:
        wheel_path = Path(td) / WHEEL
        wheel_path.write_bytes(wheel)
        env = {"PATH": os.environ.get("PATH", ""),
               "PYTHONPATH": str(wheel_path),
               "HOME": td,
               "XDG_CONFIG_HOME": td,
               "NO_COLOR": "1",
               "PYTHONDONTWRITEBYTECODE": "1"}
        # CLI can fail on missing system dependencies; report that as a hold.
        result = subprocess.run([sys.executable, "-m", "gallery_dl", "--version"],
                                cwd=td, env=env, capture_output=True, text=True,
                                timeout=15, check=False)
        if result.returncode != 0 or VERSION not in result.stdout:
            raise RuntimeError("PINNED_CLI_RUNTIME_NOT_QUALIFIED")
    print("PUBLIC_GALLERYDL_PACKAGE_PROOF=" + json.dumps({
        "version": VERSION, "wheel_sha256": SHA256,
        "instagram_extractor_sha256": instagram_sha256,
        "cli_version": VERSION,
        "scope": "public-package-and-flags-only",
        "source_access": "NOT_RUN", "media_acquisition": "NOT_RUN",
        "real_instagram": "NOT_RUN",
    }, sort_keys=True))

if __name__ == "__main__":
    run()
