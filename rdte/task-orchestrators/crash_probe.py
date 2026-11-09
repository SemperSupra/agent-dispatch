#!/usr/bin/env python3
"""R4: disposable native Dagu subprocess crash experiment on public ARM64.

Deliberately terminates a local workflow after barrier evidence while preserving
DAGU_HOME on the disposable runner. External effects are ONLY fsync'd local
JSONL events. A post-effect ambiguity is NEVER retried. This does not exercise
Agent Dispatch admission, xyOps, hosted agents, or actual business effects.
"""
import argparse
import json
import os
from pathlib import Path
import shlex
import signal
import subprocess
import sys
import tempfile
import time

STEPS = ("prepare", "branch_a", "branch_b", "verify")


def record(root: Path, step: str):
    fd = os.open(root / "effects.jsonl", os.O_WRONLY | os.O_APPEND | os.O_CREAT, 0o600)
    try:
        os.write(fd, (json.dumps({"step": step}) + "\n").encode())
        os.fsync(fd)
    finally:
        os.close(fd)


def events(root: Path):
    path = root / "effects.jsonl"
    return [json.loads(s) for s in path.read_text().splitlines()] if path.exists() else []


def perform(root: Path, step: str, mode: str):
    root.mkdir(parents=True, exist_ok=True)
    if step != "prepare" and not (root / "done-prepare").exists():
        raise RuntimeError("prepare missing")
    if step == "verify" and not all((root / ("done-" + s)).exists() for s in ("branch_a", "branch_b")):
        raise RuntimeError("join blocked")
    if step == "branch_b":
        if mode == "post-effect":
            record(root, step)
        (root / "barrier").write_text("ready\n")
        until = time.monotonic() + 65
        while not (root / "release").exists():
            if time.monotonic() >= until:
                raise RuntimeError("barrier timeout")
            time.sleep(0.07)
        if mode == "pre-effect":
            record(root, step)
    else:
        record(root, step)
    (root / ("done-" + step)).write_text("done\n")


def make_dag(root: Path, mode: str):
    path = root.parent / (root.name + ".yaml")
    lines = ["type: graph", "steps:"]
    for name, depends in (
        ("prepare", None), ("branch_a", "prepare"),
        ("branch_b", "prepare"), ("verify", "[branch_a, branch_b]")
    ):
        cmd = [sys.executable, str(Path(__file__).resolve()), "step", str(root), name, mode]
        lines.append("  - id: " + name)
        if depends:
            lines.append("    depends: " + depends)
        lines.append("    run: " + " ".join(shlex.quote(a) for a in cmd))
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    return path


def kill_isolated_workload(root: Path, proc: subprocess.Popen):
    # Terminate ONLY the newly spawned dedicated process group.
    try:
        os.killpg(proc.pid, signal.SIGKILL)
    except ProcessLookupError:
        pass
    try:
        proc.wait(timeout=7)
    except subprocess.TimeoutExpired:
        proc.kill()
        proc.wait(timeout=4)
    # Dagu steps may enter separate process groups. Inspect /proc only for
    # this unique runner-local temp root, never general process patterns.
    my_pid = os.getpid()
    for folder in Path("/proc").glob("[0-9]*"):
        try:
            pid = int(folder.name)
            if pid == my_pid:
                continue
            args = (folder / "cmdline").read_bytes()
            if (str(root).encode() in args and b"crash_probe.py" in args
                    and b"\x00step\x00" in args):
                os.kill(pid, signal.SIGKILL)
        except (OSError, ValueError, ProcessLookupError):
            pass


def probe(mode: str, base: Path):
    root = base / mode.replace("-", "_")
    root.mkdir()
    dag = make_dag(root, mode)
    run_id = "synthetic-r4-" + mode.replace("-", "-") + "-001"
    logfile = root / "start.log"
    argv = ["dagu", "start", "--run-id", run_id, str(dag)]
    started = time.monotonic()
    with logfile.open("wb") as out:
        proc = subprocess.Popen(argv, stdout=out, stderr=subprocess.STDOUT,
                                start_new_session=True)
        barrier = False
        while time.monotonic() - started < 28:
            if (root / "barrier").exists() and (root / "done-branch_a").exists():
                barrier = True
                break
            if proc.poll() is not None:
                break
            time.sleep(0.06)
        kill_isolated_workload(root, proc)
    initial = events(root)
    counts_initial = {s: sum(e["step"] == s for e in initial) for s in STEPS}
    result = {
        "mode": mode, "barrier_observed": barrier, "killed_pid": proc.pid,
        "initial_effects": counts_initial,
        "initial_verify": (root / "done-verify").exists(),
        "native_start_log_tail": logfile.read_text(errors="replace")[-450:]
    }
    # Check native persisted run identity after SIGKILL. Status may itself
    # repair stale process metadata; this is intentional observation.
    st = subprocess.run(["dagu", "status", "--run-id", run_id, str(dag)],
                        capture_output=True, text=True, timeout=18)
    result["status_exit"] = st.returncode
    result["status_tail"] = (st.stdout + st.stderr)[-650:]
    if mode == "post-effect":
        result["recovery_attempted"] = False
        result["unknown_hold"] = barrier and counts_initial["branch_b"] == 1 and not result["initial_verify"]
        result["oracle_pass"] = result["unknown_hold"]
        return result
    if not barrier or counts_initial != {"prepare": 1, "branch_a": 1, "branch_b": 0, "verify": 0}:
        result["recovery_attempted"] = False
        result["oracle_pass"] = False
        return result
    # Only PRE-effect case is safe to manually retry. Any failure/UNKNOWN
    # leaves this synthetic workcell quarantined. No automatic second retry.
    (root / "release").write_text("manual-safe-release\n")
    ret = subprocess.run(["dagu", "retry", "--run-id", run_id, str(dag)],
                         capture_output=True, text=True, timeout=70)
    final = events(root)
    counts = {s: sum(e["step"] == s for e in final) for s in STEPS}
    result.update({
        "recovery_attempted": True,
        "resume_exit": ret.returncode,
        "resume_log_tail": (ret.stdout + ret.stderr)[-800:],
        "final_effects": counts,
        "same_run_completed_once": ret.returncode == 0 and counts == dict.fromkeys(STEPS, 1)
            and (root / "done-verify").exists(),
    })
    result["oracle_pass"] = result["same_run_completed_once"]
    return result


def main():
    with tempfile.TemporaryDirectory(prefix="dagu-r4-kill-") as temp:
        base = Path(temp)
        results = [probe("pre-effect", base), probe("post-effect", base)]
        res = {
            "schema": "task-orchestrator-process-kill/v1",
            "candidate": "dagu-2.26.0",
            "architecture": os.uname().machine,
            "two_modes_completed": len(results) == 2,
            "pre_effect_resume_qualified": bool(results[0].get("same_run_completed_once")),
            "post_effect_unknown_hold": bool(results[1].get("unknown_hold")),
            "synthetic_oracle_pass": all(x["oracle_pass"] for x in results),
            "owner_admission_qualified": False,
            "host_reboot_qualified": False,
            "provider_model_qualified": False,
            "external_effect_exactly_once_qualified": False,
            "results": results
        }
        print("BAKEOFF_R4_RESULT=" + json.dumps(res, sort_keys=True), flush=True)
        if not res["synthetic_oracle_pass"]:
            # CI can remain green only when the recorded state is correctly
            # classified. A failed resume is NOT silently called success.
            print("BAKEOFF_R4_DISPOSITION=RECOVERY_NOT_QUALIFIED; inspect native receipts", flush=True)


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("verb", nargs="?", default="probe", choices=("probe", "step"))
    parser.add_argument("root", nargs="?")
    parser.add_argument("step_name", nargs="?")
    parser.add_argument("mode", nargs="?")
    args = parser.parse_args()
    if args.verb == "step":
        perform(Path(args.root), args.step_name, args.mode)
    else:
        main()
