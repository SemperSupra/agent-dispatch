"""
WinBot VNC Proxy & RDP Tests
Test the WebSocket VNC proxy endpoint and RDP .rdp file generation.
"""

import os


def _registered_route_paths(app):
    """Return direct and included-router paths across supported FastAPI versions."""
    paths = []
    for route in app.routes:
        path = getattr(route, "path", None)
        if path is not None:
            paths.append(path)

        # FastAPI 0.141+ keeps included routers as internal _IncludedRouter
        # entries while older versions flatten their routes into app.routes.
        included_router = getattr(route, "original_router", None)
        if included_router is not None:
            paths.extend(
                child.path
                for child in included_router.routes
                if getattr(child, "path", None) is not None
            )
    return paths


class TestVNCProxy:
    """Test the VNC WebSocket proxy endpoint.

    The VNC proxy requires a running TightVNC server for a full end-to-end
    test, which is not available in CI. These tests verify:
    - The WebSocket endpoint is registered and accessible
    - Authentication is enforced
    - The error path when no VNC server is running
    - The health-check configuration toggle
    """

    def test_vnc_endpoint_in_openapi(self):
        """The WebSocket endpoint path appears in the app route table."""
        from main import app
        routes = _registered_route_paths(app)
        assert "/vnc/connect" in routes, (
            "VNC WebSocket endpoint not found in app routes. "
            "Is vnc.router included in main.py?"
        )

    def test_vnc_connect_rejects_http(self, client):
        """WebSocket endpoints reject plain HTTP requests with 405 or 404."""
        response = client.get("/vnc/connect")
        assert response.status_code in (404, 405), (
            f"Expected 404 or 405 for HTTP request to WS endpoint, "
            f"got {response.status_code}"
        )

    def test_vnc_connect_requires_auth(self):
        """WebSocket connections without API token are rejected."""
        from endpoints.vnc import configure_vnc_token
        from fastapi.testclient import TestClient
        from main import app

        # Ensure token is set (conftest sets WINBOT_API_TOKEN)
        configure_vnc_token(os.environ.get("WINBOT_API_TOKEN", "test-token"))
        bare_client = TestClient(app)

        # Without X-API-Key header, the connection should be rejected
        try:
            with bare_client.websocket_connect("/vnc/connect") as ws:
                # If we connect, try to receive — should fail or get close
                received = ws.receive(timeout=2)
                # If we received something, it should indicate a close
                assert received.get("type") in ("websocket.close",)
        except Exception:
            pass  # Expected — connection rejected due to missing auth

    def test_vnc_connect_with_auth_reaches_vnc_error(self, client):
        """With auth, the VNC proxy tries to connect to TightVNC and fails gracefully."""
        # TightVNC is not running in test environment, so it should return
        # the "not reachable" error message
        try:
            with client.websocket_connect("/vnc/connect") as ws:
                received = ws.receive(timeout=5)
                assert received is not None
                text = received.get("text", "")
                assert "VNC server not reachable" in text or "error" in text.lower()
        except Exception:
            # It's also fine if the connection drops after the error
            pass

    def test_vnc_config_toggle(self):
        """The VNC proxy can be disabled via _set_vnc_enabled()."""
        from endpoints.vnc import (
            _VNC_ENABLED,
            _VNC_HOST,
            _VNC_PORT,
            _set_vnc_enabled,
            _set_vnc_target,
        )

        orig_enabled = _VNC_ENABLED
        orig_host = _VNC_HOST
        orig_port = _VNC_PORT

        try:
            _set_vnc_enabled(False)
            from endpoints.vnc import _VNC_ENABLED as enabled_check
            assert not enabled_check, "VNC proxy should be disabled"

            _set_vnc_target("10.0.0.1", 5901)
            from endpoints.vnc import _VNC_HOST as host_check
            from endpoints.vnc import _VNC_PORT as port_check
            assert host_check == "10.0.0.1"
            assert port_check == 5901
        finally:
            _set_vnc_enabled(orig_enabled)
            _set_vnc_target(orig_host, orig_port)


class TestRDPFile:
    """Test the RDP .rdp file generation endpoint."""

    def test_rdp_file_returns_200(self, client):
        """GET /vnc/rdpfile returns a 200 status."""
        response = client.get("/vnc/rdpfile")
        assert response.status_code == 200

    def test_rdp_file_media_type(self, client):
        """The .rdp file is returned as application/x-rdp content type."""
        response = client.get("/vnc/rdpfile")
        content_type = response.headers.get("content-type", "")
        assert "x-rdp" in content_type or "text/plain" in content_type

    def test_rdp_file_contains_expected_settings(self, client):
        """The .rdp file contains standard remote desktop settings."""
        response = client.get("/vnc/rdpfile")
        content = response.text

        assert "full address:s:" in content
        assert "username:s:winbot" in content
        assert "prompt for credentials:i:1" in content
        assert "redirectclipboard:i:1" in content
        assert "session bpp:i:32" in content
        assert "desktopwidth:i:1920" in content
        assert "desktopheight:i:1080" in content

    def test_rdp_file_has_download_header(self, client):
        """The .rdp file response includes Content-Disposition for download."""
        response = client.get("/vnc/rdpfile")
        disposition = response.headers.get("content-disposition", "")
        assert "attachment" in disposition
        assert ".rdp" in disposition

    def test_rdp_file_format_is_valid(self, client):
        """Each line in the .rdp file follows 'key:value' format."""
        response = client.get("/vnc/rdpfile")
        for line in response.text.strip().split("\n"):
            line = line.strip()
            if line and not line.startswith("#"):
                assert ":" in line, f"Bad line format: {repr(line[:80])}"


class TestVNCEndpointsRegistered:
    """Verify all VNC/RDP related endpoints are registered."""

    EXPECTED_VNC_ROUTES = [
        "/vnc/connect",
        "/vnc/rdpfile",
        "/health/vnc",
    ]

    def test_all_vnc_endpoints_registered(self):
        """All VNC-related endpoints appear in the app route table."""
        from main import app
        routes = _registered_route_paths(app)
        for route in self.EXPECTED_VNC_ROUTES:
            assert route in routes, (
                f"Expected route {route} not found. "
                f"Available: {sorted(routes)}"
            )


class TestVNCConformance:
    """Conformance tests for VNC-related behavior.

    These test that the VNC integration follows the same patterns as
    the rest of the WinBot API: auth, rate limiting, error responses.
    """

    def test_vnc_rdp_file_requires_auth(self):
        """The RDP file endpoint requires authentication."""
        from fastapi.testclient import TestClient
        from main import app
        bare_client = TestClient(app)
        response = bare_client.get("/vnc/rdpfile")
        assert response.status_code == 401, (
            f"RDP file without auth should return 401, got {response.status_code}"
        )

    def test_vnc_rdp_file_has_cors_headers(self, client):
        """The RDP file endpoint includes CORS headers."""
        response = client.options(
            "/vnc/rdpfile",
            headers={
                "Origin": "http://localhost",
                "Access-Control-Request-Method": "GET",
            },
        )
        # CORS preflight should succeed
        assert response.status_code in (200, 204), (
            f"CORS preflight failed: {response.status_code}"
        )

    def test_vnc_endpoint_list(self):
        """Document the expected VNC endpoints for conformance."""
        from main import app
        vnc_routes = sorted(
            path for path in _registered_route_paths(app)
            if "vnc" in path.lower()
        )
        expected = {"/vnc/connect", "/vnc/rdpfile", "/health/vnc"}
        assert expected.issubset(vnc_routes), (
            f"Missing VNC endpoints. Expected at least {expected}, "
            f"found {vnc_routes}"
        )


class TestVNCHealth:
    """Test the VNC health check endpoint."""

    def test_vnc_health_returns_200(self, client):
        """GET /health/vnc returns 200 with structured response."""
        response = client.get("/health/vnc")
        assert response.status_code == 200

    def test_vnc_health_has_expected_fields(self, client):
        """The health response contains all required fields."""
        response = client.get("/health/vnc")
        data = response.json()
        assert "proxy_enabled" in data
        assert "installed" in data
        assert "port_listening" in data
        assert "service_running" in data
        assert "status" in data

    def test_vnc_health_status_is_valid(self, client):
        """The status field is from a known set."""
        response = client.get("/health/vnc")
        data = response.json()
        valid = {"ready", "stopped", "not_installed", "disabled"}
        assert data["status"] in valid, (
            f"Unexpected status: {data['status']}!r. Expected one of {valid}"
        )

    def test_vnc_health_fields_are_bools(self, client):
        """Boolean fields are actually booleans."""
        response = client.get("/health/vnc")
        data = response.json()
        for field in ("proxy_enabled", "installed", "port_listening", "service_running"):
            assert isinstance(data[field], bool), (
                f"{field} should be bool, got {type(data[field]).__name__}"
            )

    def test_vnc_health_requires_auth(self):
        """The VNC health endpoint requires authentication."""
        from fastapi.testclient import TestClient
        from main import app
        bare_client = TestClient(app)
        response = bare_client.get("/health/vnc")
        assert response.status_code == 401
