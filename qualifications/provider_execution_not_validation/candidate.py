from __future__ import annotations

from datetime import datetime, timezone
from typing import Any


def _normalize_terminal_result(
    projection: dict[str, Any], assignment: dict[str, Any], runs: list[dict[str, Any]]
) -> dict[str, Any] | None:
    terminal = next((run for run in runs if run.get("status") == "completed"), None)
    if terminal is None:
        return None
    success = terminal.get("conclusion") == "success"
    evidence = [terminal["html_url"]] if terminal.get("html_url") else []
    now = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
    started = terminal.get("created_at") or terminal.get("updated_at") or now
    ended = terminal.get("updated_at") or started
    run_id = str(terminal.get("id") or "unknown").replace(":", "-")
    return {
        "record_type": "execution-result",
        "schema_version": 1,
        "result_id": f"{assignment['assignment_id']}.github.{run_id}",
        "contract_id": projection["contract_id"],
        "assignment_id": assignment["assignment_id"],
        "status": "completed" if success else "failed",
        "started_at": started,
        "ended_at": ended,
        "validator": {"status": "not-run", "refs": []},
        "evidence_refs": evidence,
        "produced_refs": [],
        "usage": [],
        "intervention_count": None,
        "notes": (
            "Normalized provider execution evidence. Provider completion is not "
            "independent validation or acceptance."
        ),
    }
