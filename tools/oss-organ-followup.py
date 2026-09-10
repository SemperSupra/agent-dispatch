#!/usr/bin/env python3
from __future__ import annotations

import hashlib
import importlib.util
import json
import os
import tempfile
import zipapp
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("oss_qual", ROOT / "tools" / "oss-organ-qualify.py")
qual = importlib.util.module_from_spec(spec)
assert spec and spec.loader
spec.loader.exec_module(qual)


def sha(path: Path) -> str:
    h = hashlib.sha256()
    h.update(path.read_bytes())
    return h.hexdigest()


def main() -> int:
    system, arch = qual.platform_key()
    report = {"schema": 1, "system": system, "architecture": arch, "reps": {}}
    with tempfile.TemporaryDirectory(prefix="oss-organ-followup-") as tmp:
        root = Path(tmp)
        task, evidence = qual.install_tool("task", root, system, arch)
        work = root / "task"
        work.mkdir()
        (work / "Taskfile.yml").write_text(
            "version: '3'\ntasks:\n"
            "  success:\n    desc: successful bounded workload\n    cmds:\n      - python -c \"print('ok')\"\n"
            "  fail:\n    desc: intentional failure workload\n    cmds:\n      - python -c \"raise SystemExit(7)\"\n",
            encoding="utf-8",
        )
        listing = qual.run([str(task), "--list-all", "--json"], cwd=work)
        parsed = json.loads(listing.stdout)
        task_discovery = "success" in json.dumps(parsed) and "fail" in json.dumps(parsed)
        if not task_discovery:
            raise RuntimeError(f"Task JSON discovery failed after fixture correction: {listing.stdout}")
        report["reps"]["E-005"] = {
            "purpose": "correct E-004 fixture error; distinguish tool behavior from undescribed-task listing semantics",
            "task_version": evidence["tag"],
            "list_all_json": True,
            "both_tasks_discovered": task_discovery,
        }

        source = ROOT / "lab-fixtures" / "candidate-v1" / "__main__.py"
        a = root / "a.pyz"
        b = root / "b.pyz"
        zipapp.create_archive(source.parent, target=a)
        zipapp.create_archive(source.parent, target=b)
        report["reps"]["A-003"] = {
            "purpose": "separate same-runner rebuild determinism from cross-runner artifact divergence",
            "source_sha256": sha(source),
            "source_bytes": source.stat().st_size,
            "build1_sha256": sha(a),
            "build2_sha256": sha(b),
            "same_runner_rebuild_equal": sha(a) == sha(b),
            "source_commit": os.environ.get("GITHUB_SHA"),
        }
        if not report["reps"]["A-003"]["same_runner_rebuild_equal"]:
            raise RuntimeError("same-runner zipapp rebuild was not deterministic")

    out_dir = ROOT / "qualification-results"
    out_dir.mkdir(exist_ok=True)
    out = out_dir / f"followup-{system}-{arch}.json"
    out.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps(report, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
