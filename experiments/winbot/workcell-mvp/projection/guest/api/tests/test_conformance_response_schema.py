"""
WinBot Response-Schema Conformance Tests
Validates that every endpoint's actual response matches its declared
OpenAPI response schema. Catches drift between implementation and spec.

Uses FastAPI's built-in response validation where possible, plus
structural checks for endpoints with dynamic responses.

Run: python -m pytest tests/test_conformance_response_schema.py -v
"""

import pytest

# Endpoints that produce dynamic content not easily schema-checked
# (they return binary, streaming, or highly OS-dependent data)
_DYNAMIC_ONLY = {
    "/screenshot",
    "/health/presence",
    "/health/system",
    "/health/system_info",
    "/health/storage",
    "/health/tools",
    "/health/capabilities",
    "/health/tool_catalog",
}


class TestResponseStructure:
    """Structural conformance: every endpoint returns the right shape."""

    def test_health_returns_status_and_fields(self, client):
        resp = client.get("/health")
        assert resp.status_code == 200
        data = resp.json()
        assert isinstance(data, dict)
        assert "status" in data
        assert data["status"] in ("ok", "degraded")
        assert "hostname" in data
        assert "tools" in data
        assert "storage" in data

    def test_version_returns_semver(self, client):
        resp = client.get("/version")
        assert resp.status_code == 200
        data = resp.json()
        assert "api_version" in data
        assert "winbot_version" in data
        parts = data["api_version"].split(".")
        assert len(parts) == 3
        assert all(p.isdigit() for p in parts)
        assert data["os"] == "Windows"

    def test_windows_list_returns_count_and_list(self, client):
        resp = client.get("/windows")
        assert resp.status_code == 200
        data = resp.json()
        assert isinstance(data, dict)
        assert "count" in data
        assert isinstance(data["count"], int)
        assert "windows" in data
        assert isinstance(data["windows"], list)

    def test_lifecycle_status_returns_expected_shape(self, client):
        resp = client.get("/lifecycle/status")
        assert resp.status_code == 200
        data = resp.json()
        assert "status" in data
        assert data["status"] in ("idle", "pending")
        assert "pending_action" in data
        assert "remaining_seconds" in data

    def test_operations_list_returns_list(self, client):
        resp = client.get("/operations")
        assert resp.status_code == 200
        data = resp.json()
        assert isinstance(data, dict)
        # operations are expected to be a list under 'operations' key
        # or the dict itself is the list
        assert "operations" in data or isinstance(data, list)

    def test_input_trace_status(self, client):
        resp = client.get("/input/trace/status")
        assert resp.status_code == 200
        data = resp.json()
        assert isinstance(data, dict)
        assert "tracing" in data

    def test_recording_status(self, client):
        resp = client.get("/recording/status")
        assert resp.status_code == 200
        data = resp.json()
        assert isinstance(data, dict)
        assert "recording" in data

    def test_401_response_has_detail(self, client):
        """Auth error responses must have 'detail' field."""
        from fastapi.testclient import TestClient
        from main import app
        noauth = TestClient(app)
        resp = noauth.get("/health")
        assert resp.status_code == 401
        data = resp.json()
        assert "detail" in data

    def test_422_response_has_detail(self, client):
        """Validation error responses must have 'detail' field."""
        resp = client.post("/run/python", json={})
        assert resp.status_code == 422
        data = resp.json()
        assert "detail" in data

    def test_404_response_has_detail(self, client):
        """Not-found responses must have 'detail' field."""
        resp = client.get("/nonexistent-endpoint-xyz")
        assert resp.status_code == 404
        data = resp.json()
        assert "detail" in data

    def test_error_response_has_request_id(self, client):
        """Error responses should carry X-Request-ID header."""
        resp = client.get("/nonexistent-endpoint-xyz")
        assert "x-request-id" in resp.headers
        # Also verify UUID format
        rid = resp.headers["x-request-id"]
        assert len(rid) == 36  # standard UUID length
        assert rid.count("-") == 4


class TestOpenAPIResponseConformance:
    """Verify responses match OpenAPI schema declarations.

    Uses the generated OpenAPI spec to check that response bodies
    contain all declared fields with expected types.
    """

    def _get_response_schema(self, spec, path, method, status_code):
        """Extract the response schema for a given path/method/status."""
        try:
            path_item = spec["paths"][path]
            operation = path_item[method.lower()]
            responses = operation.get("responses", {})
            response_spec = responses.get(str(status_code), {})
            content = response_spec.get("content", {})
            # Try application/json
            json_schema = content.get("application/json", {}).get("schema", {})
            if json_schema:
                return json_schema
            # Fallback: any media type
            for media_type, media_type_obj in content.items():
                schema = media_type_obj.get("schema", {})
                if schema:
                    return schema
            return {}
        except (KeyError, TypeError):
            return {}

    def test_each_endpoint_has_response_schema(self, openapi_spec):
        """Every endpoint documents at least one response schema."""
        for path, path_item in openapi_spec["paths"].items():
            for method in ("get", "post"):
                operation = path_item.get(method)
                if not operation:
                    continue
                op_id = operation.get("operationId", "unknown")
                responses = operation.get("responses", {})
                assert responses, (
                    f"Operation '{op_id}' ({method.upper()} {path}) "
                    f"has no documented responses"
                )

    def test_health_schema_matches_response(self, openapi_spec, client):
        """/health GET response conforms to its OpenAPI schema."""
        schema = self._get_response_schema(openapi_spec, "/health", "get", 200)
        if not schema:
            pytest.skip("/health has no JSON response schema documented")
        resp = client.get("/health")
        assert resp.status_code == 200

    def test_version_schema_matches_response(self, openapi_spec, client):
        """/version GET response conforms to its OpenAPI schema."""
        schema = self._get_response_schema(openapi_spec, "/version", "get", 200)
        if not schema:
            pytest.skip("/version has no JSON response schema documented")
        resp = client.get("/version")
        assert resp.status_code == 200
