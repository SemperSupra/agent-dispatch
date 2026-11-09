#!/usr/bin/env python3
"""Public-safe, no-provider synthetic orchestration benchmark; NOT an admission grant.
All candidates operate on the same four-step dependency shape:
prepare -> [branch_a, branch_b] -> verify. Checks reject missing branches.
"""
import argparse
import concurrent.futures
import json
import os
from pathlib import Path
import resource
import shutil
import statistics
import subprocess
import sys
import tempfile
import urllib.request
import time

STEPS = ("prepare", "branch_a", "branch_b", "verify")
N = 12


def action(root: Path, name: str):
    root.mkdir(parents=True, exist_ok=True)
    if name != "prepare" and not (root / "prepare").exists():
        raise RuntimeError("prepare step missing")
    if name == "verify":
        if not (root / "branch_a").exists() or not (root / "branch_b").exists():
            raise RuntimeError("independent branch missing")
    (root / name).write_text(name + "\n", encoding="utf-8")


def verify(root):
    assert all((root / s).read_text(encoding="utf-8") == s + "\n" for s in STEPS), "missing/invalid receipt"


def proc_rss_kib():
    try:
        for line in Path("/proc/self/status").read_text().splitlines():
            if line.startswith("VmRSS:"):
                return int(line.split()[1])
    except OSError:
        pass
    return None


def run_baseline(root):
    # Bare Python subprocesses, not the proprietary Agent Dispatch runtime.
    # A lower-bound execution cost, NOT Agent Dispatch performance.
    cmd = [sys.executable, str(Path(__file__).resolve()), "step", str(root)]
    subprocess.run(cmd + ["prepare"], check=True, stdout=subprocess.DEVNULL)
    with concurrent.futures.ThreadPoolExecutor(max_workers=2) as pool:
        a = pool.submit(subprocess.run, cmd + ["branch_a"], check=True, stdout=subprocess.DEVNULL)
        b = pool.submit(subprocess.run, cmd + ["branch_b"], check=True, stdout=subprocess.DEVNULL)
        a.result()
        b.result()
    subprocess.run(cmd + ["verify"], check=True, stdout=subprocess.DEVNULL)


def write_dag(dagfile, root):
    python = sys.executable
    program = Path(__file__).resolve()
    # Test artifacts are synthetic; all args internally generated.
    def step(name):
        return f"{python} {program} step {root} {name}"
    dagfile.write_text(
        "type: graph\nsteps:\n"
        f"  - id: prepare\n    run: {step('prepare')}\n"
        f"  - id: branch_a\n    depends: prepare\n    run: {step('branch_a')}\n"
        f"  - id: branch_b\n    depends: prepare\n    run: {step('branch_b')}\n"
        f"  - id: verify\n    depends: [branch_a, branch_b]\n    run: {step('verify')}\n",
        encoding="utf-8",
    )


def run_dagu(root):
    dag = root.parent / "workflow.yaml"
    write_dag(dag, root)
    p = subprocess.run(["dagu", "start", str(dag)], stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, timeout=90)
    if p.returncode:
        raise RuntimeError("dagu failed: " + p.stdout[-3500:])


def run_dbos(base):
    from dbos import DBOS
    from dbos import DBOSConfig
    @DBOS.step()
    def s(root: str, name: str):
        action(Path(root), name)
    @DBOS.workflow()
    def workflow(root: str):
        s(root, "prepare")
        # Sequential within Python workflow; marked NOT equivalent to parallel DAG.
        s(root, "branch_a")
        s(root, "branch_b")
        s(root, "verify")
    database = base / "dbos.sqlite"
    config: DBOSConfig = {
        "name": "public-bakeoff",
        "application_version": "synthetic-v1",
        "system_database_url": "sqlite:///" + str(database),
    }
    DBOS(config=config)
    DBOS.launch()
    return workflow, database


def summarize(xs):
    values = sorted(xs)
    return {
        "runs": len(xs),
        "p50_ms": round(statistics.median(xs), 3),
        "p95_ms": round(values[max(0, int((len(xs) - 1) * 0.95))], 3),
        "min_ms": round(min(xs), 3),
        "max_ms": round(max(xs), 3),
        "raw_ms": [round(v, 3) for v in xs],
    }


def benchmark(backend):
    with tempfile.TemporaryDirectory(prefix="task-bakeoff-") as tmp:
        base = Path(tmp)
        workflow = None
        dbpath = None
        if backend == "dbos":
            workflow, dbpath = run_dbos(base)
        if backend == "dagu":
            print("VERSION", subprocess.run(["dagu", "version"], capture_output=True, text=True).stdout[:200], flush=True)
        data = []
        errors = []
        for i in range(N):
            root = base / ("run%03d" % i)
            start = time.perf_counter()
            try:
                if backend == "baseline":
                    run_baseline(root)
                elif backend == "baseline_inprocess":
                    for step in STEPS:
                        action(root, step)
                elif backend == "dagu":
                    run_dagu(root)
                elif backend == "dbos":
                    workflow(str(root))
                elif backend == "restate":
                    req = urllib.request.Request("http://127.0.0.1:8080/bakeoff/run", data=json.dumps(str(root)).encode(), headers={"Content-Type":"application/json"}, method="POST")
                    with urllib.request.urlopen(req, timeout=30) as response:
                        if response.status != 200 or json.loads(response.read()) != "verified":
                            raise RuntimeError("unexpected Restate result")
                else:
                    raise ValueError(backend)
                verify(root)
            except Exception as exc:
                errors.append({"iteration": i, "type": type(exc).__name__, "message": str(exc)[:1000]})
                break
            data.append((time.perf_counter() - start) * 1000)
        result = {
            "schema": "task-orchestrator-bakeoff/v1",
            "candidate": backend,
            "architecture": os.uname().machine,
            "step_graph": "prepare -> branch_a -> branch_b -> verify" if backend in ("baseline_inprocess", "dbos", "restate") else "prepare -> [branch_a,branch_b] -> verify",
            "qualified": len(data) == N and not errors,
            "comparison_scope": ("sequential-inprocess" if backend == "baseline_inprocess" else "sequential-durable-workflow" if backend == "dbos" else "single-restate-handler-over-http" if backend == "restate" else "parallel-subprocess-graph"),
            "process_rss_kib": proc_rss_kib(),
            "child_max_rss_kib": resource.getrusage(resource.RUSAGE_CHILDREN).ru_maxrss,
            "executable_bytes": Path(shutil.which("dagu")).stat().st_size if backend == "dagu" else None,
            "db_file_bytes": dbpath.stat().st_size if dbpath and dbpath.exists() else None,
            "error": errors,
        }
        if data:
            result.update(summarize(data))
        print("BAKEOFF_RESULT=" + json.dumps(result, sort_keys=True), flush=True)
        if not result["qualified"]:
            raise SystemExit(1)


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("backend", choices=["baseline", "baseline_inprocess", "dagu", "dbos", "restate", "step"])
    parser.add_argument("path", nargs="?")
    parser.add_argument("step_name", nargs="?")
    args = parser.parse_args()
    if args.backend == "step":
        action(Path(args.path), args.step_name)
    else:
        benchmark(args.backend)
