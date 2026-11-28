#!/usr/bin/env python3
"""Compile the fixed observer and optional recovered program, then bind hashes."""
import hashlib
import json
import os
from pathlib import Path
import subprocess
from datetime import datetime, timezone

HERE = Path(__file__).resolve().parent
PACKAGE = Path("package")
COMPILER = "x86_64-w64-mingw32-gcc"


def file_info(path):
    data = path.read_bytes()
    return {"path": path.relative_to(PACKAGE).as_posix(), "bytes": len(data),
            "sha256": hashlib.sha256(data).hexdigest()}


def main():
    acquisition = json.loads((PACKAGE / "manifest.json").read_text())
    config = json.loads((HERE / "campaign.json").read_text())
    common = [COMPILER, "-std=c11", "-O2", "-Wall", "-Wextra", "-Werror", "-municode", "-Wl,--no-insert-timestamp"]
    subprocess.run([*common, str(HERE / "runtime_observer.c"), "-o", str(PACKAGE / "observer.exe")], check=True, timeout=90)
    executables = {"observer": file_info(PACKAGE / "observer.exe"),
                   "reference": file_info(PACKAGE / "reference" / "dos2unix.exe")}
    if executables["reference"]["sha256"] != acquisition["executable"]["sha256"]:
        raise ValueError("reference changed after verified acquisition")
    if config["phase"] == "validation":
        (PACKAGE / "candidate").mkdir(exist_ok=False)
        subprocess.run([*common, str(HERE / "recovered.c"), "-o", str(PACKAGE / "candidate" / "cre-dos2unix.exe")], check=True, timeout=90)
        executables["candidate"] = file_info(PACKAGE / "candidate" / "cre-dos2unix.exe")
    compiler = subprocess.run([COMPILER, "--version"], capture_output=True, text=True, check=True, timeout=10).stdout.splitlines()[0]
    manifest = {"schema": "cre.windows-re.build.v1", "phase": config["phase"],
                "source_sha": os.environ.get("GITHUB_SHA"), "run_id": os.environ.get("GITHUB_RUN_ID"),
                "run_attempt": os.environ.get("GITHUB_RUN_ATTEMPT"),
                "time_utc": datetime.now(timezone.utc).isoformat(), "compiler": compiler,
                "compiler_flags": common[1:], "executables": executables,
                "acquisition": acquisition, "bounds": {"package_upload_bytes": 8 * 1024 * 1024}}
    (PACKAGE / "build.json").write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")
    upload_bytes = sum(p.stat().st_size for p in PACKAGE.rglob("*") if p.is_file() and p.suffix != ".zip")
    if upload_bytes > manifest["bounds"]["package_upload_bytes"]:
        raise ValueError("package exceeds upload budget")
    print(json.dumps({"phase": config["phase"], "executables": executables, "upload_bytes": upload_bytes}))


if __name__ == "__main__":
    main()
