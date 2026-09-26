#!/usr/bin/env python3
"""Resolve and sanitize the standing BHADA remote survey.

This code deliberately does not contain provider implementation logic. The survey
executes BHADA's own read-only probe from an ephemeral checkout, then reduces its
output to a public-safe receipt while detailed evidence is sealed separately.
"""

from __future__ import annotations

import argparse
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


def load_config(path: Path) -> dict[str, Any]:
    value = json.loads(path.read_text(encoding="utf-8"))
    if value.get("schema") != "agent-dispatch-remote-survey/v1":
        raise ValueError("unsupported survey config schema")
    profiles = value.get("profiles")
    if not isinstance(profiles, dict) or not {"core", "broad"} <= set(profiles):
        raise ValueError("survey config requires core and broad profiles")
    return value


def choose_profile(requested: str, observed_at: datetime) -> str:
    if requested in {"core", "broad"}:
        return requested
    if requested != "auto":
        raise ValueError("profile must be auto, core, or broad")

    # Use a stable two-week calendar partition. Even ISO weeks get the broader
    # survey; odd weeks retain the cheap core pass.
    return "broad" if observed_at.isocalendar().week % 2 == 0 else "core"


def profile_providers(config: dict[str, Any], profile: str) -> list[str]:
    values = (config.get("profiles", {}).get(profile) or {}).get("providers")
    if not isinstance(values, list) or not values or not all(
        isinstance(item, str) and item.strip() for item in values
    ):
        raise ValueError(f"profile {profile!r} must contain a non-empty provider list")
    return list(dict.fromkeys(item.strip() for item in values))


def stage_statuses(row: dict[str, Any]) -> dict[str, str]:
    stages = row.get("stages")
    if not isinstance(stages, dict):
        return {}
    result: dict[str, str] = {}
    for name, value in stages.items():
        if isinstance(value, dict):
            raw = value.get("status")
        else:
            raw = value
        if raw is None:
            continue
        result[str(name)] = str(raw).upper()
    return result


def sanitize(
    raw: dict[str, Any],
    *,
    assignment_id: str,
    profile: str,
    observed_at: str,
    source_revision: str,
    workflow_run_id: str,
) -> dict[str, Any]:
    rows = raw.get("providers")
    if not isinstance(rows, list):
        raise ValueError("BHADA probe output must contain providers array")

    providers = []
    stage_counts: dict[str, int] = {}
    for row in rows:
        if not isinstance(row, dict):
            continue
        provider = row.get("provider")
        if not isinstance(provider, str) or not provider:
            continue
        stages = stage_statuses(row)
        for status in stages.values():
            stage_counts[status] = stage_counts.get(status, 0) + 1
        providers.append(
            {
                "provider": provider,
                "status": str(row.get("status") or "unknown").upper(),
                "stages": stages,
            }
        )

    provider_counts: dict[str, int] = {}
    for row in providers:
        status = row["status"]
        provider_counts[status] = provider_counts.get(status, 0) + 1

    return {
        "schema": "agent-dispatch-bhada-survey-receipt/v1",
        "assignment_id": assignment_id,
        "profile": profile,
        "observed_at": observed_at,
        "source": {
            "repository": "mark-e-deyoung/BHADA",
            "revision": source_revision,
        },
        "execution": {
            "venue": "github-actions-public-standard-runner",
            "workflow_run_id": workflow_run_id,
            "local_sovereign_required": False,
        },
        "summary": {
            "provider_count": len(providers),
            "provider_status_counts": provider_counts,
            "stage_status_counts": stage_counts,
        },
        "providers": providers,
        "redaction": {
            "urls": "omitted",
            "errors": "omitted",
            "headers": "omitted",
            "cookies": "omitted",
            "raw_result": "sealed-separately",
        },
    }


def parse_time(value: str) -> datetime:
    parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


def resolve_command(args: argparse.Namespace) -> int:
    config = load_config(args.config)
    observed_at = parse_time(args.now)
    profile = choose_profile(args.requested, observed_at)
    providers = profile_providers(config, profile)
    result = {
        "profile": profile,
        "providers": providers,
        "providers_csv": ",".join(providers),
    }
    print(json.dumps(result, sort_keys=True))
    if args.github_output:
        with args.github_output.open("a", encoding="utf-8") as handle:
            handle.write(f"profile={profile}\n")
            handle.write(f"providers={','.join(providers)}\n")
    return 0


def sanitize_command(args: argparse.Namespace) -> int:
    raw = json.loads(args.input.read_text(encoding="utf-8"))
    receipt = sanitize(
        raw,
        assignment_id=args.assignment_id,
        profile=args.profile,
        observed_at=args.observed_at,
        source_revision=args.source_revision,
        workflow_run_id=args.workflow_run_id,
    )
    args.output.write_text(json.dumps(receipt, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser()
    sub = parser.add_subparsers(dest="command", required=True)

    resolve = sub.add_parser("resolve")
    resolve.add_argument("--config", type=Path, required=True)
    resolve.add_argument("--requested", choices=["auto", "core", "broad"], default="auto")
    resolve.add_argument("--now", required=True)
    resolve.add_argument("--github-output", type=Path)
    resolve.set_defaults(func=resolve_command)

    sanitize_parser = sub.add_parser("sanitize")
    sanitize_parser.add_argument("--input", type=Path, required=True)
    sanitize_parser.add_argument("--output", type=Path, required=True)
    sanitize_parser.add_argument("--assignment-id", required=True)
    sanitize_parser.add_argument("--profile", choices=["core", "broad"], required=True)
    sanitize_parser.add_argument("--observed-at", required=True)
    sanitize_parser.add_argument("--source-revision", required=True)
    sanitize_parser.add_argument("--workflow-run-id", required=True)
    sanitize_parser.set_defaults(func=sanitize_command)

    args = parser.parse_args()
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
