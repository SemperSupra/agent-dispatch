"""API-level input tracing — compatible with WineBot /input/trace endpoints.
Records all /input/click and /input/key calls with timestamps, coordinates,
session context. Supports start/stop/status/events queries."""

import threading
import time
from collections import deque
from typing import Optional

MAX_TRACE_EVENTS = 10_000  # Ring buffer limit


class InputTracer:
    """Thread-safe input event recorder."""

    def __init__(self):
        self._lock = threading.RLock()
        self._active = False
        self._events: deque = deque(maxlen=MAX_TRACE_EVENTS)
        self._started_at: Optional[float] = None
        self._event_count = 0

    @property
    def active(self) -> bool:
        return self._active

    def start(self) -> dict:
        with self._lock:
            self._active = True
            self._started_at = time.time()
            return {"tracing": True, "started_at": self._started_at}

    def stop(self) -> dict:
        with self._lock:
            self._active = False
            return {"tracing": False, "event_count": self._event_count}

    def status(self) -> dict:
        with self._lock:
            return {
                "tracing": self._active,
                "started_at": self._started_at,
                "event_count": self._event_count,
                "max_events": MAX_TRACE_EVENTS,
            }

    def record(self, event_type: str, details: dict):
        with self._lock:
            if not self._active:
                return
            event = {
                "timestamp": time.time(),
                "type": event_type,
                **details,
            }
            self._events.append(event)
            self._event_count += 1

    def get_events(self, source: str = "api", limit: int = 100) -> dict:
        with self._lock:
            events = list(self._events)
            if limit and limit < len(events):
                events = events[-limit:]
            return {
                "source": source,
                "count": len(events),
                "total_events": self._event_count,
                "tracing": self._active,
                "events": events,
            }


# Global singleton
tracer = InputTracer()
