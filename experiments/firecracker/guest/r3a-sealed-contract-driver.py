#!/usr/bin/env python3
import hashlib
import json
import os
import pathlib
import re
import subprocess
import time

ROOT = pathlib.Path("/tmp/r3a")
SOURCE = ROOT / "scripts" / "sealed_public_execution.py"
TEST = ROOT / "tests" / "test_sealed_public_execution.py"
RESULT = pathlib.Path("/tmp/r3a-result.json")

def sha256(path):
    h = hashlib.sha256()
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()

started = time.perf_counter_ns()
cp = subprocess.run(
    ["/usr/bin/python3", "-m", "unittest", "-v", "tests/test_sealed_public_execution.py"],
    cwd=ROOT,
    capture_output=True,
    text=True,
    timeout=60,
    check=False,
)
elapsed_ns = time.perf_counter_ns() - started
combined = (cp.stdout or "") + "\n" + (cp.stderr or "")
m = re.search(r"Ran\s+(\d+)\s+tests?\s+in\s+([0-9.]+)s", combined)
tests_run = int(m.group(1)) if m else None
ok_marker = bool(re.search(r"(?:^|\n)OK(?:\n|$)", combined))

result = {
    "exit_code": int(cp.returncode),
    "elapsed_ns": elapsed_ns,
    "tests_run": tests_run,
    "ok_marker": ok_marker,
    "source_sha256": sha256(SOURCE),
    "test_sha256": sha256(TEST),
    "stdout_tail": (cp.stdout or "")[-4000:],
    "stderr_tail": (cp.stderr or "")[-8000:],
}
with RESULT.open("w", encoding="utf-8") as fh:
    json.dump(result, fh, sort_keys=True)
    fh.write("\n")
    fh.flush()
    os.fsync(fh.fileno())
os.sync()

print(
    "FIRECRACKER_R3A_CONTRACT "
    f"exit={result['exit_code']} tests={result['tests_run']} ok={1 if result['ok_marker'] else 0} "
    f"elapsed_ns={result['elapsed_ns']} source_sha256={result['source_sha256']} "
    f"test_sha256={result['test_sha256']}",
    flush=True,
)
raise SystemExit(0 if cp.returncode == 0 and ok_marker and tests_run is not None else 23)
