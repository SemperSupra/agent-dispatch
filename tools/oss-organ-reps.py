#!/usr/bin/env python3
from __future__ import annotations

import hashlib
import importlib.util
import itertools
import json
import os
import random
import shutil
import statistics
import subprocess
import sys
import tempfile
import time
import zipapp
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
QUAL_PATH = ROOT / "tools" / "oss-organ-qualify.py"
spec = importlib.util.spec_from_file_location("oss_qual", QUAL_PATH)
qual = importlib.util.module_from_spec(spec)
assert spec and spec.loader
spec.loader.exec_module(qual)


def clean_env() -> dict[str, str]:
    env = os.environ.copy()
    env.pop("QUAL_GITHUB_TOKEN", None)
    env.pop("GITHUB_TOKEN", None)
    return env


def raw(argv: list[str], cwd: Path | None = None, timeout: int = 120, env: dict[str, str] | None = None):
    return subprocess.run(
        argv,
        cwd=cwd,
        text=True,
        capture_output=True,
        timeout=timeout,
        env=env or clean_env(),
    )


def digest(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def timed(call, repeats: int = 5) -> dict:
    samples = []
    for _ in range(repeats):
        t0 = time.perf_counter()
        call()
        samples.append(time.perf_counter() - t0)
    return {
        "repeats": repeats,
        "median_seconds": statistics.median(samples),
        "min_seconds": min(samples),
        "max_seconds": max(samples),
    }


def e004(exes: dict[str, Path], root: Path, system: str) -> dict:
    work = root / "e004"
    work.mkdir()
    (work / "workload.py").write_text(
        "from pathlib import Path\n"
        "import sys\n"
        "mode=sys.argv[1]\n"
        "if mode=='fail':\n"
        "    print('intentional-failure', file=sys.stderr); raise SystemExit(7)\n"
        "Path('result.txt').write_text('alpha\\nbeta\\ngamma\\n', encoding='utf-8')\n"
        "print('workload-ok')\n",
        encoding="utf-8",
    )
    (work / "Taskfile.yml").write_text(
        "version: '3'\ntasks:\n"
        "  success:\n    cmds:\n      - python workload.py success\n"
        "  fail:\n    cmds:\n      - python workload.py fail\n",
        encoding="utf-8",
    )
    (work / "justfile").write_text(
        "success:\n    python workload.py success\n\n"
        "fail:\n    python workload.py fail\n",
        encoding="utf-8",
    )

    def check_success(argv: list[str]):
        r = raw(argv, cwd=work)
        if r.returncode != 0 or "workload-ok" not in r.stdout:
            raise RuntimeError(f"success workload failed: {argv}: {r.returncode} {r.stdout} {r.stderr}")
        p = work / "result.txt"
        if p.read_text(encoding="utf-8") != "alpha\nbeta\ngamma\n":
            raise RuntimeError("non-deterministic workload result")
        return digest(p)

    if system == "windows":
        native_success = ["cmd", "/d", "/s", "/c", "python workload.py success"]
        native_fail = ["cmd", "/d", "/s", "/c", "python workload.py fail"]
    else:
        native_success = ["/bin/sh", "-c", "python workload.py success"]
        native_fail = ["/bin/sh", "-c", "python workload.py fail"]

    commands = {
        "native": (native_success, native_fail),
        "task": ([str(exes["task"]), "success"], [str(exes["task"]), "fail"]),
        "just": ([str(exes["just"]), "--justfile", str(work / "justfile"), "success"], [str(exes["just"]), "--justfile", str(work / "justfile"), "fail"]),
        "nushell": ([str(exes["nu"]), "-c", "^python workload.py success"], [str(exes["nu"]), "-c", "^python workload.py fail"]),
    }

    result = {"workload": "write deterministic result; deliberate exit 7 failure", "engines": {}}
    expected_digest = None
    for name, (success, fail) in commands.items():
        first = check_success(success)
        second = check_success(success)
        if first != second:
            raise RuntimeError(f"{name} failed idempotence digest check")
        if expected_digest is None:
            expected_digest = first
        elif first != expected_digest:
            raise RuntimeError(f"{name} produced different semantic result")
        fr = raw(fail, cwd=work)
        if fr.returncode == 0:
            raise RuntimeError(f"{name} swallowed intentional failure")
        result["engines"][name] = {
            "idempotent_digest": first,
            "failure_returncode": fr.returncode,
            "failure_visible": "intentional-failure" in (fr.stdout + fr.stderr),
            "startup_workload_timing": timed(lambda argv=success: check_success(argv)),
        }

    task_list = raw([str(exes["task"]), "--list", "--json"], cwd=work)
    result["engines"]["task"]["machine_discovery"] = task_list.returncode == 0 and "success" in task_list.stdout
    just_list = raw([str(exes["just"]), "--justfile", str(work / "justfile"), "--summary"], cwd=work)
    result["engines"]["just"]["machine_discovery"] = just_list.returncode == 0 and "success" in just_list.stdout
    result["engines"]["nushell"]["structured_values_native"] = True
    result["engines"]["native"]["machine_discovery"] = False
    return result


def brute_opt(cost, eligible, capacity):
    t_count = len(cost)
    a_count = len(capacity)
    best = None
    used = [0] * a_count

    order = sorted(range(t_count), key=lambda t: sum(eligible[t]))

    def visit(i: int, total: int):
        nonlocal best
        if best is not None and total >= best:
            return
        if i == t_count:
            best = total
            return
        t = order[i]
        for a in range(a_count):
            if eligible[t][a] and used[a] < capacity[a]:
                used[a] += 1
                visit(i + 1, total + cost[t][a])
                used[a] -= 1

    visit(0, 0)
    return best


def c003(minizinc: Path, root: Path) -> dict:
    work = root / "c003"
    work.mkdir()
    model = work / "allocation.mzn"
    model.write_text(
        "int: T; int: A;\n"
        "set of int: Tasks=1..T; set of int: Actors=1..A;\n"
        "array[Tasks,Actors] of 0..1: eligible;\n"
        "array[Actors] of int: capacity;\n"
        "array[Tasks,Actors] of int: cost;\n"
        "array[Tasks] of var Actors: assign;\n"
        "constraint forall(t in Tasks)(eligible[t,assign[t]] = 1);\n"
        "constraint forall(a in Actors)(sum(t in Tasks)(bool2int(assign[t]=a)) <= capacity[a]);\n"
        "var int: objective = sum(t in Tasks)(cost[t,assign[t]]);\n"
        "solve minimize objective;\n"
        "output [\"objective=\", show(objective)];\n",
        encoding="utf-8",
    )
    rng = random.Random(20260910)
    cases = []
    for idx in range(20):
        T, A = 8, 4
        cost = [[rng.randint(1, 20) for _ in range(A)] for _ in range(T)]
        eligible = [[0] * A for _ in range(T)]
        capacity = [0] * A
        if idx % 5 == 0:
            for t in range(T):
                eligible[t][0] = 1
            capacity = [T - 1, T, T, T]
        else:
            base = [rng.randrange(A) for _ in range(T)]
            counts = [base.count(a) for a in range(A)]
            capacity = [counts[a] + rng.randint(0, 2) for a in range(A)]
            for t, a0 in enumerate(base):
                eligible[t][a0] = 1
                for a in range(A):
                    if rng.random() < 0.55:
                        eligible[t][a] = 1
        expected = brute_opt(cost, eligible, capacity)
        flat_e = ",".join(str(x) for row in eligible for x in row)
        flat_c = ",".join(str(x) for row in cost for x in row)
        dzn = work / f"case-{idx:02d}.dzn"
        dzn.write_text(
            f"T={T}; A={A};\n"
            f"eligible=array2d(1..T,1..A,[{flat_e}]);\n"
            f"capacity=[{','.join(map(str,capacity))}];\n"
            f"cost=array2d(1..T,1..A,[{flat_c}]);\n",
            encoding="utf-8",
        )
        t0 = time.perf_counter()
        r = raw([str(minizinc), "--solver", "gecode", str(model), str(dzn)], cwd=work, timeout=120)
        elapsed = time.perf_counter() - t0
        text = r.stdout + r.stderr
        if expected is None:
            observed = None if "UNSATISFIABLE" in text else "unexpected-feasible"
            agreement = observed is None
        else:
            marker = "objective="
            if marker not in text:
                observed = None
            else:
                tail = text.split(marker, 1)[1]
                num = "".join(ch for ch in tail.splitlines()[0] if ch in "-0123456789")
                observed = int(num) if num else None
            agreement = observed == expected
        if not agreement:
            raise RuntimeError(f"MiniZinc disagreement case {idx}: expected={expected}, observed={observed}, output={text}")
        cases.append({"case": idx, "expected": expected, "observed": observed, "seconds": elapsed, "dzn_bytes": dzn.stat().st_size})
    return {
        "seed": 20260910,
        "cases": len(cases),
        "feasible": sum(c["expected"] is not None for c in cases),
        "infeasible": sum(c["expected"] is None for c in cases),
        "agreement": sum(c["expected"] == c["observed"] for c in cases),
        "model_bytes": model.stat().st_size,
        "mean_dzn_bytes": statistics.mean(c["dzn_bytes"] for c in cases),
        "median_solver_seconds": statistics.median(c["seconds"] for c in cases),
        "max_solver_seconds": max(c["seconds"] for c in cases),
    }


def a002(root: Path) -> dict:
    work = root / "a002"
    work.mkdir()
    v1 = work / "candidate-v1.pyz"
    v2 = work / "candidate-v2.pyz"
    zipapp.create_archive(ROOT / "lab-fixtures" / "candidate-v1", target=v1)
    zipapp.create_archive(ROOT / "lab-fixtures" / "candidate-v2", target=v2)
    install = work / "install"
    install.mkdir()
    installed = install / "candidate.pyz"

    def version():
        r = raw([sys.executable, str(installed), "--version"])
        if r.returncode != 0:
            raise RuntimeError(r.stderr)
        return r.stdout.strip()

    shutil.copy2(v1, installed)
    first_digest = digest(installed)
    if version() != "candidate-probe 1.0":
        raise RuntimeError("v1 install failed")
    shutil.copy2(v1, installed)
    reinstall_digest = digest(installed)
    if reinstall_digest != first_digest or version() != "candidate-probe 1.0":
        raise RuntimeError("idempotent reinstall failed")
    shutil.copy2(v2, installed)
    second_digest = digest(installed)
    if second_digest == first_digest or version() != "candidate-probe 2.0":
        raise RuntimeError("upgrade failed")
    installed.unlink()
    if installed.exists():
        raise RuntimeError("remove failed")
    return {
        "source_commit": os.environ.get("GITHUB_SHA"),
        "artifact_format": "python-zipapp-lab-fixture",
        "v1_sha256": first_digest,
        "reinstall_same_digest": first_digest == reinstall_digest,
        "v2_sha256": second_digest,
        "upgrade_changed_digest": second_digest != first_digest,
        "remove_verified": not installed.exists(),
    }


def d002(root: Path) -> dict:
    target = root / "xa11y-site"
    target.mkdir()
    install = raw(
        [sys.executable, "-m", "pip", "install", "--disable-pip-version-check", "--only-binary=:all:", "--no-deps", "--target", str(target), "xa11y==0.14.0"],
        timeout=180,
    )
    result = {
        "version": "0.14.0",
        "wheel_installable": install.returncode == 0,
        "install_stderr_tail": install.stderr[-1200:],
        "claim_scope": "packaging/import/error semantics only; not interactive desktop dogfood",
    }
    if install.returncode != 0:
        return result
    env = clean_env()
    env["PYTHONPATH"] = str(target)
    probe_code = (
        "import json, xa11y\n"
        "d={'imported':True,'module':xa11y.__name__}\n"
        "try:\n"
        " xa11y.App.by_name('__agent_dispatch_definitely_missing__', timeout=0)\n"
        " d['missing_app']='unexpected-success'\n"
        "except Exception as e:\n"
        " d['missing_app_exception']=type(e).__name__; d['missing_app_message']=str(e)[:500]\n"
        "print(json.dumps(d))\n"
    )
    probe = raw([sys.executable, "-c", probe_code], timeout=60, env=env)
    result["probe_returncode"] = probe.returncode
    result["probe_stdout"] = probe.stdout[-1500:]
    result["probe_stderr"] = probe.stderr[-1500:]
    if probe.returncode == 0:
        try:
            result["probe"] = json.loads(probe.stdout.strip().splitlines()[-1])
        except Exception:
            pass
    return result


def main() -> int:
    system, arch = qual.platform_key()
    report = {"schema": 1, "system": system, "architecture": arch, "reps": {}}
    with tempfile.TemporaryDirectory(prefix="oss-organ-reps-") as tmp:
        root = Path(tmp)
        exes = {}
        install_evidence = {}
        for tool in ("task", "just", "nu", "minizinc"):
            exe, evidence = qual.install_tool(tool, root, system, arch)
            exes[tool] = exe
            install_evidence[tool] = evidence
        report["pinned_tools"] = install_evidence
        report["reps"]["E-004"] = e004(exes, root, system)
        report["reps"]["C-003"] = c003(exes["minizinc"], root)
        report["reps"]["A-002"] = a002(root)
        report["reps"]["D-002"] = d002(root)

    out_dir = ROOT / "qualification-results"
    out_dir.mkdir(exist_ok=True)
    out = out_dir / f"reps-{system}-{arch}.json"
    out.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps(report, indent=2, sort_keys=True))
    print(f"wrote {out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
