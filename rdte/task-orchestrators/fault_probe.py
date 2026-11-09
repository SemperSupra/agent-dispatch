#!/usr/bin/env python3
"""R2 public-safe failure/replay probe; no real actor, API, credentials, or owner effects.

Compare *identical* synthetic subprocess graphs through a bare runner and
Dagu. No replay/approval/admission functionality is attributed to either.
Expected faults are verified by a separate local oracle, not provider status.
"""
import argparse
import concurrent.futures
import json
import os
from pathlib import Path
import shlex
import subprocess
import sys
import tempfile
import time

STEPS = ("prepare", "branch_a", "branch_b", "verify")


def effects(root: Path):
    p = root / "effects.jsonl"
    if not p.exists():
        return []
    return [json.loads(line) for line in p.read_text(encoding="utf-8").splitlines()]


def perform(root: Path, step: str, mode: str):
    root.mkdir(parents=True, exist_ok=True)
    if step != "prepare" and not (root / "done-prepare").exists():
        raise RuntimeError("predecessor missing")
    if step == "verify" and not all((root / ("done-" + s)).exists() for s in ("branch_a", "branch_b")):
        raise RuntimeError("cannot join incomplete branches")
    if step == "branch_b" and mode == "before":
        raise RuntimeError("injected before-effect branch failure")
    if step == "branch_b" and mode == "once_before":
        once = root / "fault-once-marker"
        if not once.exists():
            once.write_text("failed before effect once\n", encoding="utf-8")
            raise RuntimeError("injected transient before-effect branch failure")
    # Synthetic external side effect: fsync'd append-only event. Deliberately
    # non-idempotent to detect whether a native start fences replay by itself.
    fd = os.open(root / "effects.jsonl", os.O_WRONLY | os.O_APPEND | os.O_CREAT, 0o600)
    try:
        os.write(fd, (json.dumps({"step": step}, sort_keys=True) + "\n").encode())
        os.fsync(fd)
    finally:
        os.close(fd)
    (root / ("done-" + step)).write_text("done\n", encoding="utf-8")
    if step == "branch_b" and mode == "after":
        raise RuntimeError("injected ambiguous post-effect branch failure")


def step_command(root: Path, step: str, mode: str):
    return [sys.executable, str(Path(__file__).resolve()), "step", str(root), step, mode]


def bare(root: Path, mode: str):
    def invoke(name):
        return subprocess.run(step_command(root, name, mode), capture_output=True, text=True, timeout=35)
    first = invoke("prepare")
    if first.returncode:
        return first.returncode
    with concurrent.futures.ThreadPoolExecutor(max_workers=2) as pool:
        af = pool.submit(invoke, "branch_a")
        bf = pool.submit(invoke, "branch_b")
        a, b = af.result(), bf.result()
    if a.returncode or b.returncode:
        return a.returncode or b.returncode
    return invoke("verify").returncode


def dagu(root: Path, mode: str, *, retry=False, run_id=None):
    path = root.parent / (root.name + ".yaml")
    lines = ["type: graph", "steps:"]
    for name, depends in (
        ("prepare", None), ("branch_a", "prepare"),
        ("branch_b", "prepare"), ("verify", "[branch_a, branch_b]")
    ):
        command = " ".join(shlex.quote(arg) for arg in step_command(root, name, mode))
        lines.extend([f"  - id: {name}"])
        if depends:
            lines.append(f"    depends: {depends}")
        lines.append(f"    run: {command}")
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    argv = ["dagu", "retry" if retry else "start"]
    if run_id is not None:
        argv += ["--run-id", run_id]
    argv.append(str(path))
    proc = subprocess.run(argv, capture_output=True, text=True, timeout=100)
    if proc.returncode:
        print("EXPECTED_NATIVE_FAILURE=" + json.dumps({
            "mode": mode, "exit": proc.returncode,
            "tail": (proc.stdout + proc.stderr)[-350:]
        }), flush=True)
    return proc.returncode


def test(backend: str):
    invoke = bare if backend == "baseline" else dagu
    with tempfile.TemporaryDirectory(prefix="orchestration-r2-") as temp:
        base = Path(temp)
        observed = {}
        started = time.monotonic()

        clean = base / "replay"
        first = invoke(clean, "ok")
        first_events = effects(clean)
        assert first == 0 and all((clean / ("done-" + s)).exists() for s in STEPS)
        assert len(first_events) == 4, (first, first_events)
        second = invoke(clean, "ok")
        second_events = effects(clean)
        observed["repeat_activation"] = {
            "first_exit": first, "replayed_exit": second,
            "first_effects": len(first_events), "after_replay_effects": len(second_events),
            "duplicate_effect_observed": len(second_events) > len(first_events)
        }
        # A second externally commanded start is not automatically fenced
        # by the simple bare/Dagu invocation used here.
        assert second == 0 and len(second_events) == 8, observed

        before = base / "before"
        code = invoke(before, "before")
        before_events = effects(before)
        observed["before_effect_failure"] = {
            "native_exit": code, "join_ran": (before / "done-verify").exists(),
            "failed_branch_effects": sum(e["step"] == "branch_b" for e in before_events)
        }
        assert code != 0 and not (before / "done-verify").exists()
        assert sum(e["step"] == "branch_b" for e in before_events) == 0

        after = base / "after"
        code = invoke(after, "after")
        after_events = effects(after)
        observed["ambiguous_write"] = {
            "native_exit": code, "join_ran": (after / "done-verify").exists(),
            "failed_branch_effects": sum(e["step"] == "branch_b" for e in after_events),
            "automatically_replayed": False
        }
        assert code != 0 and not (after / "done-verify").exists()
        assert sum(e["step"] == "branch_b" for e in after_events) == 1

        # Distinct R3 rep: fail once *before* B's effect and explicitly
        # resume the SAME Dagu run ID. Bare control must restart its graph.
        # This is not an authorized owner-effect retry.
        resume = base / "resume"
        if backend == "dagu":
            first_retryable = dagu(resume, "once_before", run_id="synthetic-recovery-001")
        else:
            first_retryable = bare(resume, "once_before")
        initial = effects(resume)
        assert first_retryable != 0 and not (resume / "done-verify").exists()
        assert sum(e["step"] == "branch_b" for e in initial) == 0
        if backend == "dagu":
            second_retryable = dagu(resume, "once_before", retry=True, run_id="synthetic-recovery-001")
        else:
            second_retryable = bare(resume, "once_before")
        resumed = effects(resume)
        counts = {s: sum(e["step"] == s for e in resumed) for s in STEPS}
        reused = all(counts[s] == 1 for s in STEPS)
        observed["transient_before_effect_recovery"] = {
            "initial_exit": first_retryable, "resume_exit": second_retryable,
            "first_effects": len(initial), "after_resume_effects": len(resumed),
            "effect_counts": counts,
            "completed_steps_not_reexecuted": reused,
            "mechanism": "dagu same-run-id retry" if backend == "dagu" else "bare fresh graph replay"
        }
        # A working retry is required for task-continuation qualification,
        # but non-reuse is recorded rather than concealed by forcing a PASS.
        assert second_retryable == 0 and (resume / "done-verify").exists()
        # NEVER blindly replay a post-effect error. This test deliberately
        # stops and preserves UNKNOWN, with no second attempt.
        result = {
            "schema": "task-orchestrator-fault-probe/v1",
            "candidate": backend,
            "architecture": os.uname().machine,
            "test_cases": 4,
            "synthetic_oracle_pass": True,
            "owner_admission_qualified": False,
            "external_effect_idempotency_qualified": False,
            "restart_recovery_qualified": False,
            "provider_or_model_qualified": False,
            "elapsed_ms": round((time.monotonic() - started) * 1000, 3),
            "observations": observed
        }
        print("BAKEOFF_R2_RESULT=" + json.dumps(result, sort_keys=True), flush=True)


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("backend", choices=["baseline", "dagu", "step"])
    ap.add_argument("root", nargs="?")
    ap.add_argument("step_name", nargs="?")
    ap.add_argument("mode", nargs="?")
    args = ap.parse_args()
    if args.backend == "step":
        perform(Path(args.root), args.step_name, args.mode)
    else:
        test(args.backend)
