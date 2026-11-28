#!/usr/bin/env python3
"""Fixed released-PE campaign adapter; no generic workflow command input.

The Win32 observer supplies process evidence. This adapter independently hashes
inputs, retains exact outputs, and verifies filesystem effects. Missing evidence
remains missing. It does not infer capability from a successful workflow job.
"""
from __future__ import annotations

import argparse
import hashlib
import html
import json
import os
from pathlib import Path, PurePosixPath
import platform
import shutil
import subprocess
import sys
import time
from datetime import datetime, timezone

HERE = Path(__file__).resolve().parent
MAX_FILE_BYTES = 2 * 1024 * 1024
MAX_CASE_BYTES = 4 * 1024 * 1024
MAX_REPORT_BYTES = 16 * 1024 * 1024
MAX_FILES = 100
MAX_CASES = 64


def sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def write_json(path: Path, value: object) -> None:
    data = (json.dumps(value, ensure_ascii=False, indent=2) + "\n").encode("utf-8")
    if len(data) > MAX_REPORT_BYTES:
        raise ValueError("report exceeds declared byte budget")
    path.write_bytes(data)


def safe_path(root: Path, name: str) -> Path:
    p = PurePosixPath(name)
    if not name or p.is_absolute() or any(x in ("..", ".") for x in p.parts) or "\\" in name or ":" in name:
        raise ValueError("unsafe fixture path")
    return root.joinpath(*p.parts)


def seed(root: Path, case: dict) -> None:
    root.mkdir(parents=True, exist_ok=False)
    for name in case.get("dirs", []):
        safe_path(root, name).mkdir(parents=True, exist_ok=True)
    files = list(case.get("files", []))
    generator = case.get("filegenerator")
    if generator:
        generators = generator if isinstance(generator, list) else [generator]
        for g in generators:
            repeat = g.get("repeat", 0)
            pattern = bytes.fromhex(g["pattern_hex"])
            if not isinstance(repeat, int) or repeat < 0 or repeat * len(pattern) > MAX_FILE_BYTES:
                raise ValueError("fixture generator exceeds bound")
            data = pattern * repeat + bytes.fromhex(g.get("suffix_hex", ""))
            files.append({"path": g["path"], "data_hex": data.hex()})
    if len(files) > MAX_FILES:
        raise ValueError("fixture file count exceeds bound")
    total = 0
    for f in files:
        data = bytes.fromhex(f["data_hex"])
        total += len(data)
        if len(data) > MAX_FILE_BYTES or total > MAX_CASE_BYTES:
            raise ValueError("fixture byte budget exceeded")
        p = safe_path(root, f["path"])
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_bytes(data)


def snapshot(root: Path) -> tuple[dict, dict]:
    meta, contents = {}, {}
    paths = sorted(root.rglob("*"))
    if len(paths) > MAX_FILES:
        raise ValueError("post-state file count exceeds bound")
    total = 0
    for p in paths:
        name = p.relative_to(root).as_posix()
        if p.is_symlink():
            raise ValueError("unexpected symlink in owned fixture")
        if p.is_dir():
            meta[name] = {"kind": "directory"}
        elif p.is_file():
            size = p.stat().st_size
            total += size
            if size > MAX_FILE_BYTES or total > MAX_CASE_BYTES:
                raise ValueError("post-state byte budget exceeded")
            data = p.read_bytes()
            meta[name] = {"kind": "file", "sha256": sha(data), "bytes": len(data)}
            contents[name] = data.hex()
        else:
            raise ValueError("unexpected special file in owned fixture")
    return meta, contents


def win_path(p: Path, lane: str) -> str:
    absolute = p.resolve()
    return "Z:" + str(absolute).replace("/", "\\") if lane == "wine" else str(absolute)


def run_one(case: dict, subject: str, target: Path, observer: Path, work_root: Path,
            output: Path, lane: str, mode: str = "run") -> dict:
    label = f"{subject}-{case['id']}-{mode}"
    work = work_root / label
    evidence = output / "receipts" / label
    evidence.mkdir(parents=True, exist_ok=False)
    seed(work, case)
    before, _ = snapshot(work)
    paths = {k: evidence / f"{k}.{ext}" for k, ext in
             (("receipt", "json"), ("stdout", "bin"), ("stderr", "bin"))}
    command = [win_path(observer, lane), "--receipt", win_path(paths["receipt"], lane),
               "--stdout", win_path(paths["stdout"], lane), "--stderr", win_path(paths["stderr"], lane),
               "--mode", mode, "--timeout-ms", "5000", "--", win_path(target, lane), *case["args"]]
    if lane == "wine":
        command.insert(0, os.environ.get("CRE_WINE", "wine"))
    env = dict(os.environ)
    # Target receives a further explicit whitelist from the native observer.
    env.update({"LANG": "C", "LC_ALL": "C", "LANGUAGE": "C", "WINEDEBUG": "-all"})
    launched_sha256 = sha(target.read_bytes())
    observer_sha256 = sha(observer.read_bytes())
    host_deadline = False
    start = time.monotonic()
    with (evidence / "observer-host.stdout").open("wb") as hostout, (evidence / "observer-host.stderr").open("wb") as hosterr:
        try:
            proc = subprocess.run(command, cwd=work, env=env, stdin=subprocess.DEVNULL,
                                  stdout=hostout, stderr=hosterr, timeout=35, check=False)
            observer_exit = proc.returncode
        except subprocess.TimeoutExpired:
            host_deadline = True
            observer_exit = None
    elapsed_ms = round((time.monotonic() - start) * 1000, 3)
    errors = []
    receipt = {}
    if paths["receipt"].is_file():
        if paths["receipt"].stat().st_size <= 256 * 1024:
            try:
                receipt = json.loads(paths["receipt"].read_text(encoding="utf-8"))
            except (ValueError, UnicodeError) as exc:
                errors.append("invalid observer receipt: " + type(exc).__name__)
        else:
            errors.append("observer receipt exceeds bound")
    else:
        errors.append("observer receipt unavailable")
    streams = {}
    for kind in ("stdout", "stderr"):
        if not paths[kind].is_file():
            errors.append(kind + " capture unavailable")
            streams[kind] = b""
        elif paths[kind].stat().st_size > 65536:
            errors.append(kind + " exceeded capture bound")
            streams[kind] = paths[kind].read_bytes()[:65536]
        else:
            streams[kind] = paths[kind].read_bytes()
    for kind in ("stdout", "stderr"):
        hostfile = evidence / ("observer-host." + kind)
        if hostfile.stat().st_size > 65536:
            errors.append("host diagnostic exceeded retained bound")
            with hostfile.open("rb") as f:
                bounded = f.read(65536)
            hostfile.write_bytes(bounded)
    try:
        after, files_after = snapshot(work)
    except ValueError as exc:
        errors.append(str(exc))
        after, files_after = {}, {}
    cleanup = receipt.get("cleanup", {})
    if sha(target.read_bytes()) != launched_sha256:
        errors.append("target executable changed during execution")
    for kind in ("stdout", "stderr"):
        info = receipt.get("streams", {}).get(kind, {})
        if not (info.get("eof") is True and info.get("error") == 0 and
                info.get("bytes_seen") == info.get("bytes_retained") == len(streams[kind])):
            errors.append(kind + " stream receipt disagrees with complete retained bytes")
    if receipt.get("events_dropped") != 0:
        errors.append("debug events were dropped or count unavailable")
    deadline = host_deadline or receipt.get("timed_out", False)
    truncated = receipt.get("output_overflow", False)
    capture_complete = (observer_exit == 0 and receipt.get("observer_ok") is True and
                        cleanup.get("exit_event_seen") is True and
                        cleanup.get("process_signaled") is True and
                        cleanup.get("complete") is True and
                        not deadline and not truncated and not errors)
    target_exit = receipt.get("target_exit", {})
    status = target_exit.get("code") if target_exit.get("available") else None
    obs = {"executable_sha256": launched_sha256, "observer_sha256": observer_sha256,
           "capture_complete": capture_complete, "deadline_exceeded": bool(deadline),
           "debug_available": receipt.get("created") is True and receipt.get("image", {}).get("available") is True and receipt.get("debug", {}).get("create_event_seen") is True,
           "truncated": bool(truncated), "errors": errors, "exit_code": observer_exit,
           "receipt": receipt}
    return {"id": case["id"], "subject": subject, "mode": mode, "args": case["args"],
            "observer": obs, "exit_code": status, "stdout_hex": streams["stdout"].hex(),
            "stderr_hex": streams["stderr"].hex(), "before": before, "after": after,
            "files_after": files_after, "duration_ms": elapsed_ms}


def platform_info(lane: str) -> dict:
    info = {"lane": lane, "system": platform.system(), "release": platform.release(),
            "version": platform.version(), "machine": platform.machine(),
            "python": platform.python_version(), "cpu_count": os.cpu_count(),
            "runner_os": os.environ.get("RUNNER_OS"), "runner_arch": os.environ.get("RUNNER_ARCH"),
            "runner_image": os.environ.get("ImageOS"), "runner_image_version": os.environ.get("ImageVersion"),
            "free_disk_bytes": shutil.disk_usage(Path.cwd()).free}
    if lane == "wine":
        info["wine_version"] = subprocess.run([os.environ.get("CRE_WINE", "wine"), "--version"],
                                              capture_output=True, text=True, timeout=10, check=True).stdout.strip()
    return info


def render_report(report: dict, destination: Path) -> None:
    e = html.escape
    rows = []
    for c in report["cases"]:
        stderr = bytes.fromhex(c["stderr_hex"]).decode("utf-8", errors="backslashreplace")
        changed = [name for name in sorted(set(c["before"]) | set(c["after"]))
                   if c["before"].get(name) != c["after"].get(name)]
        rows.append(f"<tr><th scope='row'>{e(c['id'])}</th><td>{e(c['subject'])}</td>"
                    f"<td>{e(str(c['exit_code']))}</td><td>{'Complete' if c['observer']['capture_complete'] else 'Incomplete'}</td>"
                    f"<td>{e(', '.join(changed) or 'None')}</td><td><pre>{e(stderr)}</pre></td></tr>")
    page = """<!doctype html><html lang="en"><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Windows program recovery — actual observations</title><style>
:root{color-scheme:light dark}body{font:1rem/1.55 system-ui,sans-serif;margin:0 auto;padding:1.5rem;max-width:100rem}
a{color:LinkText}a:focus-visible{outline:3px solid Highlight;outline-offset:4px}h1{line-height:1.2}table{border-collapse:collapse;width:100%}
th,td{padding:.65rem;border:1px solid GrayText;text-align:left;vertical-align:top}pre,code{white-space:pre-wrap;overflow-wrap:anywhere;font-size:.9rem}
.scroll{overflow:auto}caption{text-align:left;margin-bottom:.5rem;font-weight:bold}@media(prefers-reduced-motion:reduce){*{scroll-behavior:auto}}
</style><main><h1>Actual Windows program recovery</h1>"""
    page += f"<p>Platform: <strong>{e(report['platform'])}</strong>. Phase: <strong>{e(report['phase'])}</strong>. "
    page += "These are observations of the released program. A completed sensor capture does not imply behavioral compatibility.</p>"
    page += f"<p>Reference SHA-256: <code>{e(report['target_sha256'])}</code></p><p><a href='report.json'>Download complete JSON evidence</a></p>"
    page += "<div class='scroll' role='region' aria-label='Case observations' tabindex='0'><table><caption>Exit, observer health and independent file effects</caption>"
    page += "<thead><tr><th scope='col'>Case</th><th scope='col'>Program</th><th scope='col'>Exit</th><th scope='col'>Capture</th><th scope='col'>Changed paths</th><th scope='col'>Raw diagnostic text</th></tr></thead><tbody>"
    page += "".join(rows) + "</tbody></table></div><h2>Limits</h2><p>Process I/O counters are totals, not per-path syscall traces. Descendant retirement, hostile isolation, desktop accessibility and full option compatibility are not established by this CLI campaign. Exact output bytes and actuator receipts are retained in JSON.</p></main></html>"
    destination.write_text(page, encoding="utf-8")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--platform", choices=("windows", "wine"), required=True)
    parser.add_argument("--package", type=Path, required=True)
    parser.add_argument("--outputdir", type=Path, required=True)
    parser.add_argument("--workdir", type=Path, required=True)
    args = parser.parse_args()
    package, output, work = (p.resolve() for p in (args.package, args.outputdir, args.workdir))
    if output.exists() or work.exists():
        parser.error("refuse existing output or work directory")
    output.mkdir(parents=True)
    work.mkdir(parents=True)
    config = json.loads((HERE / "campaign.json").read_text())
    phase = config["phase"]
    casefile = HERE / ("discovery_cases.json" if phase == "discovery" else "validation_cases.json")
    casebytes = casefile.read_bytes()
    if phase == "validation" and sha(casebytes) != config["validation_cases_sha256"]:
        raise ValueError("frozen independent validation corpus digest mismatch")
    cases = json.loads(casebytes)["cases"]
    if len(cases) > MAX_CASES or len({c["id"] for c in cases}) != len(cases):
        raise ValueError("invalid case count or repeated identity")
    manifest = json.loads((package / "build.json").read_text())
    # Authenticate every launched image to the once-built distributed package.
    paths = {"reference": package / "reference" / "dos2unix.exe", "observer": package / "observer.exe"}
    if phase == "validation":
        paths["candidate"] = package / "candidate" / "cre-dos2unix.exe"
    for name, path in paths.items():
        if sha(path.read_bytes()) != manifest["executables"][name]["sha256"]:
            raise ValueError("executable identity mismatch before effects: " + name)
    report = {"schema": "cre.windows-re.campaign.v1", "phase": phase, "platform": args.platform,
              "time_utc": datetime.now(timezone.utc).isoformat(),
              "source_sha": os.environ.get("GITHUB_SHA"), "run_id": os.environ.get("GITHUB_RUN_ID"),
              "run_attempt": os.environ.get("GITHUB_RUN_ATTEMPT"),
              "target_sha256": manifest["executables"]["reference"]["sha256"],
              "candidate_sha256": manifest["executables"].get("candidate", {}).get("sha256"),
              "casefile_sha256": sha(casebytes), "environment": platform_info(args.platform),
              "package_manifest": manifest, "cases": [], "actuators": []}
    subjects = ("reference",) if phase == "discovery" else ("reference", "candidate")
    for subject in subjects:
        for case in cases:
            row = run_one(case, subject, paths[subject], paths["observer"], work, output, args.platform)
            report["cases"].append(row)
            print(json.dumps({"case": case["id"], "subject": subject, "exit": row["exit_code"],
                              "observation_complete": row["observer"]["capture_complete"]}), flush=True)
            write_json(output / "report.json", report)
    control_case = {"id": "actuator-entry", "args": ["-n", "input.txt", "output.txt"],
                    "files": [{"path": "input.txt", "data_hex": "6f776e65640d0a636f6e74726f6c0d0a"}]}
    for subject in subjects:
        for mode in ("breakpoint", "abort", "run"):
            row = run_one(control_case, subject, paths[subject], paths["observer"], work, output, args.platform, mode)
            bp = row["observer"]["receipt"].get("breakpoint", {})
            if mode == "breakpoint":
                passed = all(bp.get(k) is True for k in ("installed", "hit", "context_read", "byte_restored", "protection_restored", "context_rewound", "continued", "install_readback", "byte_restore_verified", "original_known", "install_protection_restored")) and row["exit_code"] == 0 and row["files_after"].get("output.txt") == "6f776e65640a636f6e74726f6c0a"
                image = row["observer"]["receipt"].get("image", {})
                try:
                    entry = int(image["entry_address_hex"], 16)
                    passed = passed and int(bp["rip_before_hex"], 16) == entry + 1 and int(bp["rip_after_hex"], 16) == entry
                except (KeyError, TypeError, ValueError):
                    passed = False
            elif mode == "abort":
                receipt = row["observer"]["receipt"]
                termination = receipt.get("termination", {})
                passed = receipt.get("cancelled") is True and receipt.get("abort_before_first_continue") is True and termination.get("attempted") is True and termination.get("succeeded") is True and row["exit_code"] not in (None, 0) and "output.txt" not in row["after"] and row["before"] == row["after"]
            else:
                passed = row["exit_code"] == 0 and row["files_after"].get("output.txt") == "6f776e65640a636f6e74726f6c0a"
            row["oracle_passed"] = passed and row["observer"]["capture_complete"]
            report["actuators"].append(row)
    write_json(output / "report.json", report)
    render_report(report, output / "index.html")
    complete = all(c["observer"]["capture_complete"] for c in report["cases"])
    actuation = all(c["oracle_passed"] for c in report["actuators"])
    write_json(output / "summary.json", {"phase": phase, "platform": args.platform,
                                         "case_count": len(report["cases"]), "observations_complete": complete,
                                         "actuator_oracles_passed": actuation})
    print(json.dumps({"observations_complete": complete, "actuator_oracles_passed": actuation}), flush=True)
    return 0 if complete and actuation else 1


if __name__ == "__main__":
    raise SystemExit(main())
