#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import pathlib
import re

NONCE_RE = re.compile(r"^[A-Za-z0-9_-]{16,64}$")
INSTANCE_RE = re.compile(r"^[A-Za-z0-9_.-]{1,64}$")
PREFIX = "AGENT_DISPATCH_V1_NONCE="


class SeedError(RuntimeError):
    pass


def validate_token(value: str, pattern: re.Pattern[str], label: str) -> str:
    if not pattern.fullmatch(value):
        raise SeedError(f"{label} violates deterministic seed contract")
    return value


def render_seed(nonce: str, instance_id: str) -> tuple[str, str]:
    nonce = validate_token(nonce, NONCE_RE, "nonce")
    instance_id = validate_token(instance_id, INSTANCE_RE, "instance-id")
    meta = json.dumps(
        {"instance-id": instance_id, "local-hostname": "rdtev1"},
        sort_keys=True,
        separators=(",", ":"),
    ) + "\n"
    user = (
        "#!/bin/sh\n"
        "set -eu\n"
        f"nonce='{nonce}'\n"
        f"printf '%s%s\\n' '{PREFIX}' \"$nonce\" >/dev/ttyS0\n"
        f"printf '%s%s\\n' '{PREFIX}' \"$nonce\" >/dev/console 2>/dev/null || true\n"
    )
    return meta, user


def render_v2_observation_seed(nonce: str, instance_id: str) -> tuple[str, str]:
    nonce = validate_token(nonce, NONCE_RE, "nonce")
    instance_id = validate_token(instance_id, INSTANCE_RE, "instance-id")
    meta = json.dumps(
        {"instance-id": instance_id, "local-hostname": "rdtev2"},
        sort_keys=True,
        separators=(",", ":"),
    ) + "\n"
    user = (
        "#!/bin/sh\n"
        "set -eu\n"
        f"nonce='{nonce}'\n"
        "kvm=0\n"
        "cpu=0\n"
        "[ -c /dev/kvm ] && kvm=1 || true\n"
        "grep -Eq '(^|[[:space:]])(vmx|svm)([[:space:]]|$)' /proc/cpuinfo && cpu=1 || true\n"
        f"printf '%s%s\\n' '{PREFIX}' \"$nonce\" >/dev/ttyS0\n"
        "printf 'AGENT_DISPATCH_V2_KVM_PRESENT=%s\\n' \"$kvm\" >/dev/ttyS0\n"
        "printf 'AGENT_DISPATCH_V2_CPU_VMX_SVM=%s\\n' \"$cpu\" >/dev/ttyS0\n"
    )
    return meta, user


def write_seed(out_dir: pathlib.Path, nonce: str, instance_id: str) -> None:
    meta, user = render_seed(nonce, instance_id)
    out_dir.mkdir(parents=True, exist_ok=True)
    (out_dir / "meta-data").write_text(meta, encoding="utf-8")
    user_path = out_dir / "user-data"
    user_path.write_text(user, encoding="utf-8")
    user_path.chmod(0o755)


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--nonce", required=True)
    ap.add_argument("--instance-id", required=True)
    ap.add_argument("--out-dir", type=pathlib.Path, required=True)
    args = ap.parse_args()
    try:
        write_seed(args.out_dir, args.nonce, args.instance_id)
    except (SeedError, OSError) as exc:
        print(f"ERROR: {exc}")
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
