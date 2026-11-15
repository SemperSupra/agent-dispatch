#!/usr/bin/env python3
"""Bounded public-only source-pinned OpenWorker permission primitive interview.

Loads *real upstream* MIT-licensed standalone modules, checks their Git blob
identities and evaluates safe vs dangerous command classification without
executing any commands, accessing accounts or invoking any model. No private
source/data, arbitrary URLs or provider calls.
"""
from __future__ import annotations

import hashlib
import importlib.util
import json
from pathlib import Path
import sys
import tempfile
import urllib.request

SCHEMA = "openworker-public-policy-interview/v1"
REPOSITORY = "andrewyng/openworker"
COMMIT = "ecb445490fc054d52b8ea610d97ba947f57033d2"
SOURCES = {
    "coworker/readonly.py": "d621e606eea85be031c27237b0bc2ffcdfe590cb",
    "coworker/sandbox/network_profiles.py": "4f253ac14839d522abeff8d8dd2cc21066d2d3f3",
    "LICENSE": "60d3824636ee279c14389ea0b858f00fe0c4a913",
}
MAX_SOURCE_BYTES = 90_000
BASE = "https://raw.githubusercontent.com/andrewyng/openworker/" + COMMIT + "/"


class QualificationError(ValueError):
    pass


def git_blob_sha(data: bytes) -> str:
    prefix = b"blob " + str(len(data)).encode("ascii") + b"\x00"
    return hashlib.sha1(prefix + data).hexdigest()


def verify_bytes(path: str, data: bytes) -> None:
    if path not in SOURCES or not 30 <= len(data) <= MAX_SOURCE_BYTES:
        raise QualificationError("UPSTREAM_CONTENT_NOT_ALLOWED")
    if git_blob_sha(data) != SOURCES[path]:
        raise QualificationError("PINNED_UPSTREAM_GIT_BLOB_MISMATCH")


def download(path: str) -> bytes:
    if path not in SOURCES:
        raise QualificationError("UNREVIEWED_PATH")
    url = BASE + path
    request = urllib.request.Request(
        url, headers={"User-Agent": "mail-research-public-probe/1.0"})
    with urllib.request.urlopen(request, timeout=12) as response:
        if response.geturl() != url:
            raise QualificationError("UNREVIEWED_REDIRECT")
        if response.status != 200:
            raise QualificationError("UPSTREAM_HTTP_NON_200")
        data = response.read(MAX_SOURCE_BYTES + 1)
    verify_bytes(path, data)
    return data


def load_module(name: str, file: Path):
    spec = importlib.util.spec_from_file_location(name, file)
    if spec is None or spec.loader is None:
        raise QualificationError("UNSUPPORTED_SOURCE_FORMAT")
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


def run_case_matrix(readonly, profile) -> dict:
    positives = {
        "bash-ls": ("ls", "bash"),
        "bash-cat": ("cat README.md", "bash"),
    }
    negatives = {
        "write-rm": ("rm -rf .", "bash"),
        "find-exec": ("find . -exec rm {} +", "bash"),
        "network-curl": ("curl https://example.invalid", "bash"),
        "inline-eval": ("python3 -c 'print(1)'", "bash"),
        "write-redirect": ("cat README.md > credentials.txt", "bash"),
        "chain-write": ("git status && rm -rf .", "bash"),
    }
    allowed = {name: readonly.is_readonly_command(command, shell=shell)
               for name, (command, shell) in positives.items()}
    rejected = {name: not readonly.is_readonly_command(command, shell=shell)
                for name, (command, shell) in negatives.items()}
    valid_host = profile.clean_host("https://example.invalid") == "example.invalid:443"
    unknown_profile_rejected = False
    try:
        profile.check("unreviewed")
    except ValueError:
        unknown_profile_rejected = True
    return {
        "allowed_controls": len(positives),
        "blocked_controls": len(negatives),
        "safe_all_allowed": all(allowed.values()),
        "dangerous_all_rejected": all(rejected.values()),
        "host_normalization_verified": valid_host,
        "unknown_network_profile_rejected": unknown_profile_rejected,
        "individual_safe": allowed,
        "individual_blocked": rejected,
    }


def qualify() -> dict:
    with tempfile.TemporaryDirectory(prefix="public-openworker-test-") as temp:
        root = Path(temp)
        for path in SOURCES:
            dest = root / path
            dest.parent.mkdir(parents=True, exist_ok=True)
            dest.write_bytes(download(path))
        license_text = (root / "LICENSE").read_text(encoding="utf-8")
        if not license_text.startswith("MIT License") or "Copyright" not in license_text:
            raise QualificationError("UPSTREAM_LICENSE_UNQUALIFIED")
        readonly = load_module("public_openworker_readonly",
                               root / "coworker" / "readonly.py")
        profile = load_module("public_openworker_network_profile",
                              root / "coworker" / "sandbox" / "network_profiles.py")
        cases = run_case_matrix(readonly, profile)
    qualified = (
        cases["safe_all_allowed"]
        and cases["dangerous_all_rejected"]
        and cases["host_normalization_verified"]
        and cases["unknown_network_profile_rejected"])
    return {
        "schema": SCHEMA,
        "classification": "UPSTREAM_POLICY_PRIMITIVES_ONLY",
        "upstream_repository": REPOSITORY,
        "upstream_commit": COMMIT,
        "readonly_blob_sha": SOURCES["coworker/readonly.py"],
        "license": "MIT",
        "case_matrix": cases,
        "qualified": bool(qualified),
        "model_inference": False,
        "mail_credential_access": False,
        "shell_commands_executed": False,
        "network_origin": "raw.githubusercontent.com",
    }


def main() -> int:
    try:
        result = qualify()
    except (OSError, ValueError, UnicodeError) as exc:
        print("OPENWORKER_PINNED_SOURCE_BLOCKED:" +
              (str(exc) if isinstance(exc, QualificationError) else
               "SOURCE_ACQUISITION_OR_IMPORT_FAILED"), file=sys.stderr)
        return 2
    print(json.dumps(result, sort_keys=True))
    return 0 if result["qualified"] else 2


if __name__ == "__main__":
    raise SystemExit(main())
