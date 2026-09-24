#!/usr/bin/env python3
"""Small monotonic lifecycle timing helper for Firecracker RDTE receipts."""
from __future__ import annotations

import contextlib
import time


class LifecycleTimer:
    """Collect ordered stage durations without coupling to an execution venue."""

    def __init__(self) -> None:
        self._origin = time.perf_counter()
        self._stages: list[dict] = []

    @contextlib.contextmanager
    def stage(self, name: str, scope: str):
        if scope not in {"portable", "venue"}:
            raise ValueError(f"invalid timing scope: {scope}")
        started = time.perf_counter()
        try:
            yield
        finally:
            ended = time.perf_counter()
            self._stages.append(
                {
                    "name": name,
                    "scope": scope,
                    "elapsed_ms": round((ended - started) * 1000.0, 3),
                    "cumulative_ms": round((ended - self._origin) * 1000.0, 3),
                    "derived": False,
                }
            )

    def add(self, name: str, scope: str, elapsed_ms: float, *, derived: bool = True) -> None:
        if scope not in {"portable", "venue"}:
            raise ValueError(f"invalid timing scope: {scope}")
        self._stages.append(
            {
                "name": name,
                "scope": scope,
                "elapsed_ms": round(float(elapsed_ms), 3),
                "cumulative_ms": round((time.perf_counter() - self._origin) * 1000.0, 3),
                "derived": bool(derived),
            }
        )

    def receipt(self) -> dict:
        total_ms = round((time.perf_counter() - self._origin) * 1000.0, 3)
        portable_ms = round(
            sum(stage["elapsed_ms"] for stage in self._stages if stage["scope"] == "portable" and not stage["derived"]),
            3,
        )
        venue_ms = round(
            sum(stage["elapsed_ms"] for stage in self._stages if stage["scope"] == "venue" and not stage["derived"]),
            3,
        )
        return {
            "clock": "time.perf_counter",
            "stages": list(self._stages),
            "total_elapsed_ms": total_ms,
            "portable_stage_sum_ms": portable_ms,
            "venue_stage_sum_ms": venue_ms,
            "note": (
                "Stage sums exclude derived observations and untimed Python/control overhead. "
                "Derived guest timings may overlap host-side lifecycle stages and are retained for diagnosis."
            ),
        }
