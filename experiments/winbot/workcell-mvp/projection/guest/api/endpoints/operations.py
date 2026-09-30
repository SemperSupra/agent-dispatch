"""Operation telemetry — compatible with WineBot /operations endpoint.
Records timing, status, and context for all API operations.
Thread-safe, in-memory, ring-buffered."""

import threading
import time
import uuid
from collections import OrderedDict
from typing import Optional

MAX_OPERATIONS = 500  # Ring buffer limit


class OperationTracker:
    """Thread-safe recorder for API operation metrics."""

    def __init__(self):
        self._lock = threading.RLock()
        self._ops: OrderedDict[str, dict] = OrderedDict()
        self._total = 0

    def start(self, category: str, context: Optional[dict] = None) -> str:
        """Begin tracking an operation. Returns operation_id."""
        op_id = uuid.uuid4().hex[:12]
        with self._lock:
            self._ops[op_id] = {
                "operation_id": op_id,
                "category": category,
                "status": "running",
                "started_at": time.time(),
                "completed_at": None,
                "duration_seconds": None,
                "context": context or {},
                "error": None,
            }
            # Evict oldest if ring buffer is full
            while len(self._ops) > MAX_OPERATIONS:
                self._ops.popitem(last=False)
        return op_id

    def complete(self, op_id: str, error: Optional[str] = None):
        """Mark an operation as completed."""
        with self._lock:
            if op_id in self._ops:
                op = self._ops[op_id]
                op["completed_at"] = time.time()
                op["duration_seconds"] = round(op["completed_at"] - op["started_at"], 3)
                op["status"] = "error" if error else "completed"
                op["error"] = error
                self._total += 1

    def list_operations(self, limit: int = 50, status: Optional[str] = None) -> dict:
        """List recent operations, optionally filtered by status."""
        with self._lock:
            ops = list(self._ops.values())
            if status:
                ops = [o for o in ops if o["status"] == status]
            ops.sort(key=lambda o: o["started_at"], reverse=True)
            if limit:
                ops = ops[:limit]
            return {
                "count": len(ops),
                "total_operations": self._total,
                "operations": ops,
            }

    def get_operation(self, op_id: str) -> Optional[dict]:
        """Get a specific operation by ID."""
        with self._lock:
            return self._ops.get(op_id)


# Context manager for convenience
class TimedOperation:
    """Context manager that automatically tracks operation timing."""

    def __init__(self, category: str, context: Optional[dict] = None):
        self.category = category
        self.context = context
        self.op_id = None

    def __enter__(self):
        self.op_id = ops.start(self.category, self.context)
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        error = str(exc_val) if exc_val else None
        ops.complete(self.op_id, error)
        return False  # Don't suppress exceptions


# Global singleton
ops = OperationTracker()
