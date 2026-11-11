#!/usr/bin/env python3
"""Hard no-taint acceptance for tooling; execute compiler in fully disposable OCI.

Docker daemon runs ONLY on a one-job ephemeral public GitHub-hosted runner. The
user's persistent dev, build, deployment host is NEVER a runner for this test.
All writes including build binaries/cache remain inside private tmpfs mount(s).
"""
import hashlib
import json
import os
import pathlib
import subprocess
import sys

ROOT = pathlib.Path("experiments/supratoolbelt-zero-taint").absolute()
WORKSPACE = pathlib.Path(os.environ["GITHUB_WORKSPACE"]).absolute()
HOME = pathlib.Path.home().absolute()
IMAGE = os.environ["DISPOSABLE_BUILDER_IMAGE"]
OUT = pathlib.Path("zero-taint-receipt.json")

WATCHED = [
    HOME / ".local",
    HOME / ".cache",
    HOME / ".npm",
    HOME / ".config" / "containers",
    HOME / ".qwen",
    HOME / ".codex",
    HOME / ".opencode",
    WORKSPACE / ".local",
    WORKSPACE / ".venv",
    WORKSPACE / "node_modules",
]

def digest_file(path):
    h = hashlib.sha256()
    with open(path, "rb") as stream:
        while True:
            chunk = stream.read(256 * 1024)
            if not chunk: break
            h.update(chunk)
    return h.hexdigest()

def tree_fingerprint(path):
    if not path.exists() and not path.is_symlink(): return "ABSENT"
    if path.is_symlink(): return "LINK:" + os.readlink(path)
    if path.is_file(): return "FILE:" + digest_file(path)
    h = hashlib.sha256()
    for current, folders, files in os.walk(path, followlinks=False):
        folders.sort()
        files.sort()
        for name in folders + files:
            p = pathlib.Path(current) / name
            rel = str(p.relative_to(path))
            if p.is_symlink(): marker = "LINK:" + os.readlink(p)
            elif p.is_file(): marker = "FILE:" + digest_file(p)
            else: marker = "DIR"
            h.update((rel + ":" + marker + "\n").encode())
    return "TREE:" + h.hexdigest()

def run(args):
    proc = subprocess.run(args, text=True, capture_output=True, timeout=180)
    if proc.returncode:
        raise RuntimeError(
            f"Command exit {proc.returncode}; stdout={proc.stdout[-850:]}; "
            f"stderr={proc.stderr[-850:]}"
        )
    return proc.stdout

def cell(command):
    args = [
        "docker", "run", "--rm", "--pull=never",
        "--user", "65532:65532", "--read-only", "--network", "none",
        "--cap-drop", "ALL", "--security-opt", "no-new-privileges",
        "--pids-limit", "128", "--memory", "1024m", "--cpus", "2",
        "--tmpfs", "/tmp:rw,exec,nosuid,nodev,size=512m,mode=1777",
        "--tmpfs", "/work:rw,exec,nosuid,nodev,size=96m,mode=1777",
        "--mount", f"type=bind,source={ROOT},target=/src,readonly",
        "-e", "HOME=/tmp/home", "-e", "GOCACHE=/tmp/go-cache",
        "-e", "GOPATH=/tmp/gopath", "-e", "GOMODCACHE=/tmp/gopath/pkg/mod",
        "-e", "GOTOOLCHAIN=local", "-e", "GO111MODULE=off",
        "-e", "CGO_ENABLED=0", "-e", "TMPDIR=/tmp",
        "-w", "/src", IMAGE, "/bin/sh", "-eu", "-c", command,
    ]
    return run(args)

def main():
    baseline = {str(path):tree_fingerprint(path) for path in WATCHED}
    source_before = {p.name:digest_file(p) for p in ROOT.iterdir() if p.is_file()}
    report = {
        "schema": "m1-zero-taint-ephemeral-build-acceptance-v1",
        "scope": "one-job disposable GitHub-hosted runner plus two ephemeral OCI cells",
        "builderImageDigest": IMAGE,
        "cellUid": "65532:65532",
        "rootfsReadOnly": True,
        "sourceReadonly": True,
        "networkDisabled": True,
        "noHostRuntimeSocket": True,
        "toolCachesOnlyTmpfs": True,
        "persistentHostAccess": False,
        "hostHomePollutionAbsent": False,
        "sourceUnchanged": False,
        "cellDestroyedAndToolOutputAbsentInSecondCell": False,
        "passed": False,
        "limits": [
            "This test does not prove an app's external DB survives full VM destruction",
            "GitHub-hosted runner is ephemeral; Docker daemon image cache is discarded with it",
            "No persistent workstation/TrueNAS/VPS or shared VM is touched",
            "Docker engine belongs to the disposable CI runner, not exposed in workload",
            "No actual Agentgateway or Open WebUI production deployment",
        ],
    }
    try:
        first = cell(
            "mkdir -p /tmp/home /tmp/go-cache /tmp/gopath /work;"
            "test ! -e /work/probe;"
            "if touch /src/should-not-write 2>/dev/null; then exit 44; fi;"
            "if touch /home/should-not-write 2>/dev/null; then exit 45; fi;"
            "go build -trimpath -o /work/probe /src/probe.go;"
            "/work/probe;"
            "test -s /work/probe;"
            "test -s /work/generated/receipt.txt"
        )
        assert "M1_ZERO_TAINT_BUILD_OK" in first
        second = cell(
            "test ! -e /work/probe;"
            "test ! -e /work/generated/receipt.txt;"
            "test ! -e /tmp/go-cache;"
            "echo M1_SECOND_CELL_EMPTY"
        )
        report["cellDestroyedAndToolOutputAbsentInSecondCell"] = "M1_SECOND_CELL_EMPTY" in second
        after = {str(path):tree_fingerprint(path) for path in WATCHED}
        report["hostHomePollutionAbsent"] = after == baseline
        report["sourceUnchanged"] = (
            source_before == {p.name:digest_file(p) for p in ROOT.iterdir() if p.is_file()}
            and not (ROOT / "should-not-write").exists()
        )
        report["passed"] = all((
            report["cellDestroyedAndToolOutputAbsentInSecondCell"],
            report["hostHomePollutionAbsent"],
            report["sourceUnchanged"],
        ))
    except Exception as exc:
        report["failure"] = repr(exc)[:1400]
    OUT.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n")
    print(json.dumps(report, indent=2, sort_keys=True))
    return 0 if report["passed"] else 1

if __name__ == "__main__":
    sys.exit(main())
