#!/usr/bin/env python3
from __future__ import annotations

import hashlib
import json
import os
import platform
import shutil
import stat
import subprocess
import sys
import tarfile
import tempfile
import time
import urllib.request
import zipfile
from pathlib import Path

VERSIONS = {
    "task": ("go-task/task", "v3.53.1"),
    "just": ("casey/just", "1.58.0"),
    "nu": ("nushell/nushell", "0.115.1"),
    "minizinc": ("MiniZinc/libminizinc", "2.10.1"),
}

def platform_key() -> tuple[str, str]:
    system = platform.system().lower()
    raw_arch = platform.machine().lower()
    if raw_arch in {"x86_64", "amd64"}:
        arch = "x64"
    elif raw_arch in {"arm64", "aarch64"}:
        arch = "arm64"
    else:
        raise RuntimeError(f"unsupported architecture: {raw_arch}")
    if system not in {"linux", "darwin", "windows"}:
        raise RuntimeError(f"unsupported operating system: {system}")
    return system, arch

def asset_name(tool: str, system: str, arch: str) -> str:
    if tool == "task":
        os_name = {"linux": "linux", "darwin": "darwin", "windows": "windows"}[system]
        arch_name = {"x64": "amd64", "arm64": "arm64"}[arch]
        ext = "zip" if system == "windows" else "tar.gz"
        return f"task_{os_name}_{arch_name}.{ext}"
    if tool == "just":
        target = {
            ("linux", "x64"): "x86_64-unknown-linux-musl",
            ("linux", "arm64"): "aarch64-unknown-linux-musl",
            ("darwin", "x64"): "x86_64-apple-darwin",
            ("darwin", "arm64"): "aarch64-apple-darwin",
            ("windows", "x64"): "x86_64-pc-windows-msvc",
            ("windows", "arm64"): "aarch64-pc-windows-msvc",
        }[(system, arch)]
        ext = "zip" if system == "windows" else "tar.gz"
        return f"just-1.58.0-{target}.{ext}"
    if tool == "nu":
        target = {
            ("linux", "x64"): "x86_64-unknown-linux-gnu",
            ("linux", "arm64"): "aarch64-unknown-linux-gnu",
            ("darwin", "x64"): "x86_64-apple-darwin",
            ("darwin", "arm64"): "aarch64-apple-darwin",
            ("windows", "x64"): "x86_64-pc-windows-msvc",
            ("windows", "arm64"): "aarch64-pc-windows-msvc",
        }[(system, arch)]
        ext = "zip" if system == "windows" else "tar.gz"
        return f"nu-0.115.1-{target}.{ext}"
    if tool == "minizinc":
        target = {
            ("linux", "x64"): "x86_64-linux-gnu",
            ("linux", "arm64"): "aarch64-linux-gnu",
            ("darwin", "x64"): "x86_64-apple-darwin",
            ("darwin", "arm64"): "aarch64-apple-darwin",
            ("windows", "x64"): "x86_64-windows",
            ("windows", "arm64"): "aarch64-windows",
        }[(system, arch)]
        ext = "zip" if system == "windows" else "tar.gz"
        return f"MiniZinc-2.10.1-{target}.{ext}"
    raise KeyError(tool)

def request_json(url: str) -> dict:
    headers = {
        "Accept": "application/vnd.github+json",
        "User-Agent": "agent-dispatch-oss-organ-qualification/1",
        "X-GitHub-Api-Version": "2022-11-28",
    }
    token = os.environ.get("QUAL_GITHUB_TOKEN")
    if token:
        headers["Authorization"] = f"Bearer {token}"
    req = urllib.request.Request(url, headers=headers)
    with urllib.request.urlopen(req, timeout=30) as response:
        return json.load(response)

def download(url: str, destination: Path) -> None:
    req = urllib.request.Request(url, headers={"User-Agent": "agent-dispatch-oss-organ-qualification/1"})
    last_error = None
    for attempt in range(3):
        try:
            with urllib.request.urlopen(req, timeout=60) as response, destination.open("wb") as out:
                shutil.copyfileobj(response, out)
            return
        except Exception as exc:
            last_error = exc
            if attempt == 2:
                break
            time.sleep(2 ** attempt)
    raise RuntimeError(f"download failed after retries: {url}: {last_error}")

def verify_sha256(path: Path, digest_field: str | None) -> str:
    if not digest_field or not digest_field.startswith("sha256:"):
        raise RuntimeError(f"release asset has no GitHub SHA-256 digest: {path.name}")
    expected = digest_field.split(":", 1)[1].lower()
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    actual = h.hexdigest()
    if actual != expected:
        raise RuntimeError(f"SHA-256 mismatch for {path.name}: expected {expected}, got {actual}")
    return actual

def extract(archive: Path, destination: Path) -> None:
    destination.mkdir(parents=True, exist_ok=True)
    root = destination.resolve()
    if archive.suffix.lower() == ".zip":
        with zipfile.ZipFile(archive) as z:
            for member in z.infolist():
                target = (destination / member.filename).resolve()
                if root not in target.parents and target != root:
                    raise RuntimeError(f"unsafe archive path in {archive.name}: {member.filename}")
            z.extractall(destination)
    else:
        with tarfile.open(archive, "r:gz") as t:
            for member in t.getmembers():
                target = (destination / member.name).resolve()
                if root not in target.parents and target != root:
                    raise RuntimeError(f"unsafe archive path in {archive.name}: {member.name}")
            t.extractall(destination)

def find_executable(root: Path, basename: str, system: str) -> Path:
    expected = basename + (".exe" if system == "windows" else "")
    candidates = [p for p in root.rglob(expected) if p.is_file()]
    if not candidates:
        raise RuntimeError(f"could not find {expected} under {root}")
    candidates.sort(key=lambda p: (len(p.parts), len(str(p))))
    exe = candidates[0]
    if system != "windows":
        exe.chmod(exe.stat().st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)
    return exe

def run(argv: list[str], cwd: Path | None = None) -> subprocess.CompletedProcess[str]:
    clean_env = os.environ.copy()
    clean_env.pop("QUAL_GITHUB_TOKEN", None)
    clean_env.pop("GITHUB_TOKEN", None)
    result = subprocess.run(
        argv,
        cwd=cwd,
        text=True,
        capture_output=True,
        timeout=120,
        env=clean_env,
    )
    if result.returncode != 0:
        raise RuntimeError(
            f"command failed ({result.returncode}): {argv}\nstdout:\n{result.stdout}\nstderr:\n{result.stderr}"
        )
    return result

def install_tool(tool: str, root: Path, system: str, arch: str) -> tuple[Path, dict]:
    repo, tag = VERSIONS[tool]
    metadata = request_json(f"https://api.github.com/repos/{repo}/releases/tags/{tag}")
    name = asset_name(tool, system, arch)
    match = next((a for a in metadata.get("assets", []) if a.get("name") == name), None)
    if match is None:
        available = [a.get("name") for a in metadata.get("assets", [])]
        raise RuntimeError(f"{repo}@{tag} has no expected asset {name}; available={available}")
    archive = root / name
    download(match["browser_download_url"], archive)
    digest = verify_sha256(archive, match.get("digest"))
    unpacked = root / f"{tool}-unpacked"
    extract(archive, unpacked)
    exe_name = {"task": "task", "just": "just", "nu": "nu", "minizinc": "minizinc"}[tool]
    exe = find_executable(unpacked, exe_name, system)
    return exe, {
        "repo": repo,
        "tag": tag,
        "asset": name,
        "sha256": digest,
        "executable": str(exe),
    }

def exercise_task(exe: Path, root: Path) -> dict:
    work = root / "task-work"
    work.mkdir()
    (work / "Taskfile.yml").write_text(
        "version: '3'\n"
        "tasks:\n"
        "  hello:\n"
        "    desc: portable qualification probe\n"
        "    cmds:\n"
        "      - echo task-ok\n",
        encoding="utf-8",
    )
    version = run([str(exe), "--version"]).stdout.strip()
    listing = run([str(exe), "--list", "--json"], cwd=work).stdout
    parsed = json.loads(listing)
    if "hello" not in json.dumps(parsed):
        raise RuntimeError(f"Task JSON discovery did not expose hello: {listing}")
    execution = run([str(exe), "hello"], cwd=work)
    if "task-ok" not in execution.stdout:
        raise RuntimeError(f"Task execution missing marker: {execution.stdout}")
    return {"version": version, "structured_discovery": True, "execution": "task-ok"}

def exercise_just(exe: Path, root: Path) -> dict:
    work = root / "just-work"
    work.mkdir()
    justfile = work / "justfile"
    justfile.write_text("hello:\n    @echo just-ok\n", encoding="utf-8")
    version = run([str(exe), "--version"]).stdout.strip()
    summary = run([str(exe), "--justfile", str(justfile), "--summary"], cwd=work).stdout
    if "hello" not in summary:
        raise RuntimeError(f"just summary did not expose hello: {summary}")
    execution = run([str(exe), "--justfile", str(justfile), "hello"], cwd=work)
    if "just-ok" not in execution.stdout:
        raise RuntimeError(f"just execution missing marker: {execution.stdout}")
    return {"version": version, "static_discovery": True, "execution": "just-ok"}

def exercise_nu(exe: Path) -> dict:
    version = run([str(exe), "--version"]).stdout.strip()
    result = run([str(exe), "-c", "print (([1 2 3] | math sum) == 6)"]).stdout.strip().lower()
    if "true" not in result:
        raise RuntimeError(f"Nushell structured-pipeline probe failed: {result}")
    return {"version": version, "structured_pipeline": True}

def exercise_minizinc(exe: Path, root: Path) -> dict:
    version_result = run([str(exe), "--version"])
    version = (version_result.stdout + version_result.stderr).strip()
    work = root / "minizinc-work"
    work.mkdir()
    model = work / "probe.mzn"
    model.write_text(
        "var 0..10: x;\n"
        "constraint x >= 7;\n"
        "solve minimize x;\n"
        "output [show(x)];\n",
        encoding="utf-8",
    )
    solved = run([str(exe), "--solver", "gecode", str(model)], cwd=work)
    if "7" not in solved.stdout:
        raise RuntimeError(f"MiniZinc optimization probe did not return expected optimum 7: {solved.stdout}")
    return {"version": version, "optimization_probe": "optimal x=7"}

def main() -> int:
    system, arch = platform_key()
    report = {
        "schema": 1,
        "system": system,
        "architecture": arch,
        "python": sys.version,
        "tools": {},
    }
    with tempfile.TemporaryDirectory(prefix="oss-organ-qualification-") as tmp:
        root = Path(tmp)
        executables = {}
        for tool in ("task", "just", "nu", "minizinc"):
            exe, evidence = install_tool(tool, root, system, arch)
            executables[tool] = exe
            report["tools"][tool] = evidence

        report["tools"]["task"]["probe"] = exercise_task(executables["task"], root)
        report["tools"]["just"]["probe"] = exercise_just(executables["just"], root)
        report["tools"]["nu"]["probe"] = exercise_nu(executables["nu"])
        report["tools"]["minizinc"]["probe"] = exercise_minizinc(executables["minizinc"], root)

    out_dir = Path("qualification-results")
    out_dir.mkdir(exist_ok=True)
    out = out_dir / f"report-{system}-{arch}.json"
    out.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps(report, indent=2, sort_keys=True))
    print(f"wrote {out}")
    return 0

if __name__ == "__main__":
    raise SystemExit(main())
