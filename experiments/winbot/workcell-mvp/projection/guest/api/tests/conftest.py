"""
WinBot API Test Fixtures
Shared setup for all API tests.
"""

import os
import sys

import pytest

# Ensure the api package is importable
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

# Set a test token for tests (auth is required by default)
os.environ["WINBOT_API_TOKEN"] = "test-token"


@pytest.fixture
def client():
    """Return a FastAPI TestClient for the WinBot API with auth token attached."""
    from fastapi.testclient import TestClient
    from main import app
    return TestClient(app, headers={"X-API-Key": "test-token"})


@pytest.fixture
def app():
    """Return the FastAPI app for schema inspection."""
    from main import app
    return app


@pytest.fixture
def openapi_spec(app):
    """Return the generated OpenAPI schema."""
    return app.openapi()


# Expected WineBot-compatible endpoints that WinBot claims to support
EXPECTED_ENDPOINTS = [
    # Method, Path, Status
    ("GET", "/health", 200),
    ("GET", "/health/system", 200),
    ("GET", "/health/system_info", 200),
    ("GET", "/health/tools", 200),
    ("GET", "/health/storage", 200),
    ("GET", "/health/presence", 200),
    ("GET", "/health/capabilities", 200),
    ("GET", "/health/tool_catalog", 200),
    ("GET", "/screenshot", 200),
    ("POST", "/apps/run", 422),  # 422 without body (validation)
    ("POST", "/run/ahk", 422),
    ("POST", "/run/autoit", 422),
    ("POST", "/run/python", 422),
    ("POST", "/input/mouse/click", 422),
    ("POST", "/input/mouse/move", 422),
    ("POST", "/input/keyboard/type", 422),
    ("POST", "/input/keyboard/press", 422),
    ("GET", "/windows", 200),
    ("POST", "/windows/focus", 422),
    ("POST", "/lifecycle/shutdown", 200),
    ("POST", "/lifecycle/restart", 200),
    ("POST", "/lifecycle/cancel", 200),
    ("GET", "/lifecycle/status", 200),
    ("GET", "/version", 200),
    ("GET", "/vnc/rdpfile", 200),
]
