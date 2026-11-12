"""Fixed, offline wheel identity inventory for synthetic public toolchain builds."""
from __future__ import annotations
import hashlib
import json
from pathlib import Path
import re

MAX_WHEEL_BYTES = 25 * 1024 * 1024
WHEEL_NAME = re.compile(r"^[A-Za-z0-9_.+-]+\.whl$")


def index_wheels(root: Path) -> list[dict]:
    paths = sorted(root.glob("*.whl"))
    if len(paths) != 6:
        raise ValueError("expected six pinned dependency wheels")
    result = []
    for path in paths:
        if (path.is_symlink() or not path.is_file()
                or not WHEEL_NAME.fullmatch(path.name)
                or not 0 < path.stat().st_size <= MAX_WHEEL_BYTES):
            raise ValueError("unqualified wheel identity")
        result.append({"filename": path.name,
                       "sha256": hashlib.sha256(path.read_bytes()).hexdigest()})
    return result


if __name__ == "__main__":
    data = {"schema": "public-python-wheel-candidate/v1",
            "source_kind": "fixed_public_synthetic_only",
            "wheels": index_wheels(Path("/opt/wheels"))}
    Path("/opt/wheel-evidence.json").write_text(json.dumps(data, sort_keys=True) + "\n")
