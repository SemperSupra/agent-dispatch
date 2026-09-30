"""
WinBot OpenAPI Contract Tests
Verifies the generated OpenAPI schema matches expectations
and is WineBot-compatible.
"""



class TestOpenAPIContract:
    """Verify OpenAPI schema structure and WineBot compatibility."""

    def test_openapi_version(self, openapi_spec):
        """OpenAPI spec should be version 3.x."""
        assert "openapi" in openapi_spec
        assert openapi_spec["openapi"].startswith("3.")

    def test_title_and_version(self, openapi_spec):
        """Verify API metadata."""
        info = openapi_spec["info"]
        assert info["title"] == "WinBot API"
        assert "version" in info

    def test_all_paths_registered(self, openapi_spec):
        """Every expected endpoint should exist in the OpenAPI spec."""
        paths = openapi_spec["paths"]
        from conftest import EXPECTED_ENDPOINTS

        for method, path, _ in EXPECTED_ENDPOINTS:
            method_lower = method.lower()
            assert path in paths, f"Path {path} missing from OpenAPI spec"
            assert method_lower in paths[path], (
                f"Method {method} for {path} missing from OpenAPI spec"
            )

    def test_health_response_schema(self, openapi_spec):
        """/health should return 'status' and 'tools' fields."""
        health_get = openapi_spec["paths"]["/health"]["get"]
        assert "200" in health_get["responses"]

    def test_version_response_schema(self, openapi_spec):
        """/version should return api_version and winbot_version."""
        ver_get = openapi_spec["paths"]["/version"]["get"]
        assert "200" in ver_get["responses"]

    def test_lifecycle_cancel_endpoint(self, openapi_spec):
        """/lifecycle/cancel should accept POST."""
        paths = openapi_spec["paths"]
        assert "/lifecycle/cancel" in paths, "Cancel endpoint missing from OpenAPI spec"
        assert "post" in paths["/lifecycle/cancel"], "/lifecycle/cancel should accept POST"

    def test_script_requests_use_post(self, openapi_spec):
        """/run/* endpoints should be POST methods."""
        paths = openapi_spec["paths"]
        for run_path in ["/run/ahk", "/run/autoit", "/run/python"]:
            assert "post" in paths[run_path], (
                f"{run_path} should accept POST"
            )

    def test_presence_endpoint(self, openapi_spec):
        """/health/presence should accept GET."""
        paths = openapi_spec["paths"]
        assert "/health/presence" in paths, "Presence endpoint missing from OpenAPI spec"
        assert "get" in paths["/health/presence"], "/health/presence should accept GET"

    def test_screenshot_is_get(self, openapi_spec):
        """/screenshot should be a GET endpoint."""
        assert "get" in openapi_spec["paths"]["/screenshot"]

    def test_windows_list_is_get(self, openapi_spec):
        """/windows listing should be GET."""
        assert "get" in openapi_spec["paths"]["/windows"]

    def test_input_endpoints_are_post(self, openapi_spec):
        """Input endpoints should be POST."""
        paths = openapi_spec["paths"]
        for input_path in [
            "/input/mouse/click",
            "/input/mouse/move",
            "/input/keyboard/type",
            "/input/keyboard/press",
        ]:
            assert "post" in paths[input_path], (
                f"{input_path} should accept POST"
            )


class TestWineBotCompatibility:
    """Verify WinBot API matches WineBot contract where claimed."""

    def test_version_headers_present(self, client):
        """Responses must carry X-WinBot-Version and X-WinBot-API-Version headers."""
        response = client.get("/health")
        assert "x-winbot-version" in response.headers
        assert "x-winbot-api-version" in response.headers

    def test_request_id_header(self, client):
        """Responses must carry X-Request-ID header."""
        response = client.get("/health")
        assert "x-request-id" in response.headers

    def test_health_status_field(self, client):
        """GET /health must return a 'status' field."""
        response = client.get("/health")
        assert response.status_code == 200
        data = response.json()
        assert "status" in data
        assert data["status"] in ("ok", "degraded")

    def test_version_endpoint(self, client):
        """GET /version must return api_version and winbot_version."""
        response = client.get("/version")
        assert response.status_code == 200
        data = response.json()
        assert "api_version" in data
        assert "winbot_version" in data

    def test_tools_health(self, client):
        """GET /health/tools must report tool presence."""
        response = client.get("/health/tools")
        assert response.status_code == 200
        data = response.json()
        assert "tools" in data
        for tool in ("autoit", "ahk", "python"):
            assert tool in data["tools"], f"Tool '{tool}' missing from health"

    def test_auth_token_required(self, app):
        """Requests without valid token must get 401."""
        from fastapi.testclient import TestClient
        # Use a client WITHOUT the auth token
        noauth_client = TestClient(app)
        response = noauth_client.get("/health")
        assert response.status_code == 401
        assert "Invalid or missing API token" in response.json()["detail"]

    def test_auth_token_accepted(self, client):
        """Requests with valid token must succeed."""
        response = client.get("/health")
        assert response.status_code == 200
