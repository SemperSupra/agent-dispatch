#!/usr/bin/env python3
"""Public-safe R6 concurrency/replay stress: same four-step graph, no owner effects."""
import argparse
import concurrent.futures
import json
import os
from pathlib import Path
import shlex
import statistics
import subprocess
import sys
import tempfile
import time

STEPS = ("prepare", "branch_a", "branch_b", "verify")


def effect(root, step, pause=0):
    root.mkdir(exist_ok=True, parents=True)
    if step != "prepare" and not (root / "done-prepare").exists():
        raise RuntimeError("missing prepare")
    if step == "verify" and not all((root / ("done-" + s)).exists() for s in ("branch_a", "branch_b")):
        raise RuntimeError("incomplete join")
    if pause and step == "branch_b":
        time.sleep(pause)
    elif step in ("branch_a", "branch_b"):
        time.sleep(0.08)
    with (root / "effects.jsonl").open("a", encoding="utf8") as f:
        f.write(json.dumps({"step": step}) + "\n")
        f.flush()
        os.fsync(f.fileno())
    (root / ("done-" + step)).write_text("complete\n")


def read_effects(root):
    p = root / "effects.jsonl"
    return [json.loads(line) for line in p.read_text().splitlines()] if p.exists() else []


def command(root, step, pause=0):
    return [sys.executable, str(Path(__file__).resolve()), "step", str(root), step, str(pause)]


def graph(root, pause=0):
    path = root.parent / (root.name + ".yaml")
    lines = ["type: graph", "steps:"]
    for step, deps in (
        ("prepare", None), ("branch_a", "prepare"),
        ("branch_b", "prepare"), ("verify", "[branch_a, branch_b]")):
        lines += [f"  - id: {step}"]
        if deps:
            lines += [f"    depends: {deps}"]
        lines += ["    run: " + " ".join(shlex.quote(a) for a in command(root, step, pause))]
    path.write_text("\n".join(lines) + "\n")
    return path


def run_one(candidate, root, pause=0, run_id=None):
    start = time.monotonic()
    try:
        if candidate == "dagu":
            path = graph(root, pause)
            args = ["dagu", "start", "--run-id", run_id or "synthetic-" + root.name, str(path)]
            process = subprocess.run(args, capture_output=True, text=True, timeout=60)
            code, tail = process.returncode, (process.stdout + process.stderr)[-300:]
        else:
            def exec_step(step):
                return subprocess.run(command(root, step, pause), capture_output=True,
                                      text=True, timeout=30)
            first = exec_step("prepare")
            if first.returncode:
                code, tail = first.returncode, (first.stdout + first.stderr)[-300:]
            else:
                with concurrent.futures.ThreadPoolExecutor(max_workers=2) as pool:
                    af = pool.submit(exec_step, "branch_a")
                    bf = pool.submit(exec_step, "branch_b")
                    a, b = af.result(), bf.result()
                if a.returncode or b.returncode:
                    code, tail = a.returncode or b.returncode, (a.stdout + a.stderr + b.stdout + b.stderr)[-300:]
                else:
                    v = exec_step("verify")
                    code, tail = v.returncode, (v.stdout + v.stderr)[-300:]
    except Exception as exc:
        code, tail = -1, type(exc).__name__ + ": " + str(exc)[:180]
    effects = read_effects(root)
    counts = {s: sum(e["step"] == s for e in effects) for s in STEPS}
    return {
        "code": code, "ms": round((time.monotonic() - start) * 1000, 3),
        "counts": counts, "once": code == 0 and all(n == 1 for n in counts.values()),
        "detail_if_not_success": tail if code else ""
    }


def main(candidate):
    with tempfile.TemporaryDirectory(prefix="orchestrator-r6-") as tmp:
        base = Path(tmp)
        batches = []
        for n in (1, 4, 8):
            tick = time.monotonic()
            with concurrent.futures.ThreadPoolExecutor(max_workers=n) as pool:
                futures = [pool.submit(run_one, candidate, base / f"group-{n}-run-{i}")
                           for i in range(n)]
                results = [f.result() for f in futures]
            latencies = sorted(r["ms"] for r in results)
            batches.append({
                "concurrency": n, "submitted": n,
                "all_four_steps_once": sum(r["once"] for r in results),
                "failed_runs": [
                    {"index": i, "exit": r["code"], "reason": r["detail_if_not_success"]}
                    for i, r in enumerate(results) if not r["once"]
                ],
                "wall_ms": round((time.monotonic() - tick) * 1000, 3),
                "median_ms": round(statistics.median(latencies), 3),
                "p95_observed_ms": latencies[max(0, int((len(latencies)-1) * 0.95))],
                "throughput_tasks_per_sec": round(n / max(.000001, time.monotonic()-tick), 2)
            })
        duplicate = None
        if candidate == "dagu":
            root = base / "overlap-same-run-id"
            # Two competing native launches with same exact DAG & run ID.
            with concurrent.futures.ThreadPoolExecutor(max_workers=2) as pool:
                x = pool.submit(run_one, candidate, root, 1.0, "synthetic-same-identity-001")
                time.sleep(0.10)
                y = pool.submit(run_one, candidate, root, 1.0, "synthetic-same-identity-001")
                pair = [x.result(), y.result()]
            effects = read_effects(root)
            duplicate = {
                "native_exit_codes": [r["code"] for r in pair],
                "effect_counts": {s: sum(e["step"] == s for e in effects) for s in STEPS},
                "exactly_one_launcher_succeeded": sum(r["code"] == 0 for r in pair) == 1,
                "native_lock_behavior_observed": sum(r["code"] == 0 for r in pair) == 1,
                "errors": [r["detail_if_not_success"] for r in pair if r["code"] != 0]
            }
        result = {
            "schema": "task-orchestrator-concurrency/v1",
            "candidate": candidate, "arch": os.uname().machine,
            "synthetic_no_provider_effects": True,
            "batches": batches,
            "same_run_id_overlap": duplicate,
            "throughput_qualified_for_this_fixture": all(
                row["all_four_steps_once"] == row["submitted"] for row in batches),
            "owner_idempotency_qualified": False,
            "xyops_integration_qualified": False,
            "operator_attention_measured": False
        }
        print("BAKEOFF_R6_RESULT=" + json.dumps(result, sort_keys=True), flush=True)
        if not result["throughput_qualified_for_this_fixture"]:
            raise SystemExit(2)


if __name__ == "__main__":
    p = argparse.ArgumentParser()
    p.add_argument("candidate", choices=("baseline", "dagu", "step"))
    p.add_argument("root", nargs="?")
    p.add_argument("step_name", nargs="?")
    p.add_argument("pause", nargs="?", default="0")
    a = p.parse_args()
    if a.candidate == "step":
        effect(Path(a.root), a.step_name, float(a.pause))
    else:
        main(a.candidate)
