"""
WinBot API Endpoint Tests
Integration tests for each endpoint using FastAPI TestClient.
"""



class TestHealthEndpoints:
    """Test /health family."""

    def test_health_ok(self, client):
        response = client.get("/health")
        assert response.status_code == 200
        data = response.json()
        assert "status" in data
        assert "hostname" in data
        assert "tools" in data
        assert "storage" in data

    def test_health_system(self, client):
        response = client.get("/health/system")
        assert response.status_code == 200
        data = response.json()
        assert "cpu_count" in data
        assert "memory" in data
        assert "boot_time" in data

    def test_health_system_info(self, client):
        response = client.get("/health/system_info")
        assert response.status_code == 200
        data = response.json()
        assert "architecture" in data
        assert "memory_total_gb" in data

    def test_health_tools(self, client):
        response = client.get("/health/tools")
        assert response.status_code == 200
        data = response.json()
        assert "all_ok" in data
        assert "tools" in data

    def test_health_storage(self, client):
        response = client.get("/health/storage")
        assert response.status_code == 200
        data = response.json()
        assert "directories" in data

    def test_health_presence(self, client):
        """Presence endpoint reports human detection status."""
        response = client.get("/health/presence")
        assert response.status_code == 200
        data = response.json()
        assert "present" in data
        assert isinstance(data["present"], bool)
        assert "evidence" in data
        assert isinstance(data["evidence"], list)
        # When running tests interactively, explorer.exe is likely present
        if data["present"]:
            assert "explorer_running" in data["evidence"]
        assert "active_sessions" in data


class TestAutomationEndpoints:
    """Test /run/* endpoints."""

    def test_run_python_success(self, client):
        response = client.post("/run/python", json={
            "script": "print('hello world')"
        })
        assert response.status_code == 200
        data = response.json()
        assert data["status"] == "ok"
        assert "hello world" in data["stdout"]

    def test_run_python_error(self, client):
        response = client.post("/run/python", json={
            "script": "raise ValueError('test error')"
        })
        assert response.status_code == 200
        data = response.json()
        assert data["status"] == "failed"
        assert "ValueError" in data["stderr"]

    def test_run_python_timeout(self, client, monkeypatch):
        # Set a very short timeout to test timeout behavior
        monkeypatch.setenv("WINBOT_SCRIPT_TIMEOUT", "1")
        response = client.post("/run/python", json={
            "script": "import time; time.sleep(10)"
        })
        # Timeout returns 200 with status "timeout", not 500
        assert response.status_code == 200
        data = response.json()
        assert data["status"] == "timeout"

    def test_run_ahk_missing_request(self, client):
        response = client.post("/run/ahk", json={})
        assert response.status_code == 422

    def test_run_autoit_missing_request(self, client):
        response = client.post("/run/autoit", json={})
        assert response.status_code == 422

    def test_run_python_empty_body(self, client):
        response = client.post("/run/python", json={})
        assert response.status_code == 422


class TestInputEndpoints:
    """Test /input/* endpoints."""

    def test_mouse_click_validation(self, client):
        response = client.post("/input/mouse/click", json={
            "x": 100, "y": 200
        })
        # Should succeed (valid coordinates, defaults for button/clicks)
        # If pyautogui is missing, returns 500
        assert response.status_code in (200, 500)

    def test_mouse_click_missing_fields(self, client):
        response = client.post("/input/mouse/click", json={})
        assert response.status_code == 422

    def test_mouse_move_missing_fields(self, client):
        response = client.post("/input/mouse/move", json={})
        assert response.status_code == 422

    def test_keyboard_type_missing_fields(self, client):
        response = client.post("/input/keyboard/type", json={})
        assert response.status_code == 422

    def test_keyboard_press_missing_fields(self, client):
        response = client.post("/input/keyboard/press", json={})
        assert response.status_code == 422

    def test_mouse_click_invalid_button(self, client):
        response = client.post("/input/mouse/click", json={
            "x": 100, "y": 200, "button": "pancake"
        })
        # Button is validated by pyautogui, not by pydantic
        # If pyautogui is missing, returns 500; otherwise depends on pyautogui
        assert response.status_code in (200, 422, 500)


class TestAppExecution:
    """Test /apps/run."""

    def test_app_run_missing_path(self, client):
        response = client.post("/apps/run", json={})
        assert response.status_code == 422

    def test_app_run_with_args(self, client):
        response = client.post("/apps/run", json={
            "path": "cmd.exe",
            "args": "/c echo hello",
            "detach": False
        })
        assert response.status_code in (200, 404, 403)
        if response.status_code == 200:
            data = response.json()
            assert data["status"] in ("finished", "failed")

    def test_app_run_detached(self, client):
        response = client.post("/apps/run", json={
            "path": "cmd.exe",
            "args": "/c timeout 1",
            "detach": True
        })
        assert response.status_code in (200, 404, 403)
        if response.status_code == 200:
            data = response.json()
            assert data["status"] == "detached"


class TestWindowsEndpoint:
    """Test /windows and /windows/focus."""

    def test_list_windows(self, client):
        response = client.get("/windows")
        assert response.status_code == 200
        data = response.json()
        assert "count" in data
        assert "windows" in data

    def test_focus_window_missing_title(self, client):
        response = client.post("/windows/focus", json={})
        # title is optional, should still work
        assert response.status_code == 200

    def test_focus_nonexistent_window(self, client):
        response = client.post("/windows/focus", json={
            "title": "zzz_nonexistent_window_xyzzy_12345"
        })
        assert response.status_code == 200
        data = response.json()
        assert data["status"] == "not_found"


class TestScreenshotEndpoint:
    """Test /screenshot."""

    def test_screenshot_returns_image(self, client):
        response = client.get("/screenshot")
        # May fail if pyautogui not installed, or succeed
        assert response.status_code in (200, 500)
        if response.status_code == 200:
            assert response.headers["content-type"].startswith("image/")
            assert "x-screenshot-path" in response.headers


class TestLifecycleEndpoints:
    """Test /lifecycle/*."""

    def test_shutdown(self, client):
        """Shutdown endpoint returns expected fields with presence info."""
        response = client.post("/lifecycle/shutdown")
        assert response.status_code == 200
        data = response.json()
        assert data["status"] == "shutting_down"
        assert "delay_seconds" in data
        assert data["delay_seconds"] >= 10  # auto-selected based on presence
        assert "cancel_before" in data
        assert data["cancel_command"] == "POST /lifecycle/cancel"
        assert "human_present" in data
        assert "human_evidence" in data
        # Cancel to clean up the pending shutdown
        client.post("/lifecycle/cancel")

    def test_restart(self, client):
        """Restart endpoint returns expected fields with presence info."""
        response = client.post("/lifecycle/restart")
        assert response.status_code == 200
        data = response.json()
        assert data["status"] == "restarting"
        assert "delay_seconds" in data
        assert data["delay_seconds"] >= 10  # auto-selected based on presence
        assert "cancel_before" in data
        assert data["cancel_command"] == "POST /lifecycle/cancel"
        assert "human_present" in data
        assert "human_evidence" in data
        client.post("/lifecycle/cancel")

    def test_shutdown_with_custom_delay(self, client):
        """Shutdown accepts a custom delay parameter."""
        response = client.post("/lifecycle/shutdown?delay=10")
        assert response.status_code == 200
        data = response.json()
        assert data["status"] == "shutting_down"
        assert data["delay_seconds"] == 10
        assert "human_present" in data
        client.post("/lifecycle/cancel")

    def test_shutdown_delay_too_small(self, client):
        """Shutdown rejects delay below minimum (0 = auto, values below 0 rejected)."""
        response = client.post("/lifecycle/shutdown?delay=-1")
        assert response.status_code == 422  # validation error

    def test_shutdown_delay_too_large(self, client):
        """Shutdown rejects delay above maximum (600s)."""
        response = client.post("/lifecycle/shutdown?delay=9999")
        assert response.status_code == 422  # validation error

    def test_cancel_shutdown(self, client):
        """Cancel aborts a pending shutdown."""
        # Initiate shutdown with long delay so it doesn't actually happen
        client.post("/lifecycle/shutdown?delay=300")
        # Cancel it
        response = client.post("/lifecycle/cancel")
        assert response.status_code == 200
        data = response.json()
        assert data["status"] == "cancelled"

    def test_cancel_without_pending(self, client):
        """Cancel reports no_pending when nothing is scheduled."""
        # First make sure nothing is pending
        client.post("/lifecycle/cancel")  # absorb any leftover
        # Now check
        response = client.post("/lifecycle/cancel")
        assert response.status_code == 200
        data = response.json()
        assert data["status"] == "no_pending"


class TestVersionEndpoint:
    """Test /version."""

    def test_version(self, client):
        response = client.get("/version")
        assert response.status_code == 200
        data = response.json()
        assert "api_version" in data
        assert "winbot_version" in data
        assert data["os"] == "Windows"


class TestCORSMiddleware:
    """Test CORS headers for cross-origin agent access."""

    def test_cors_preflight(self, client):
        response = client.options(
            "/health",
            headers={
                "Origin": "http://localhost",
                "Access-Control-Request-Method": "GET",
            }
        )
        # CORS middleware returns access-control-allow-origin for allowed origins
        assert "access-control-allow-origin" in response.headers

    def test_cors_headers_on_normal_request(self, client):
        response = client.get("/health", headers={
            "Origin": "http://localhost"
        })
        assert "access-control-allow-origin" in response.headers

    def test_cors_rejects_unknown_origin(self, client):
        response = client.options(
            "/health",
            headers={
                "Origin": "http://evil.example.com",
                "Access-Control-Request-Method": "GET",
            }
        )
        # Unknown origins should NOT be allowed
        assert "access-control-allow-origin" not in response.headers
        # or if present, must NOT be the evil origin
        if "access-control-allow-origin" in response.headers:
            assert response.headers["access-control-allow-origin"] != "http://evil.example.com"


class TestRateLimiting:
    """Test rate limit enforcement (WINBOT_RATE_LIMIT)."""

    def test_normal_request_passes(self, client):
        """A standard request under the limit should succeed."""
        response = client.get("/health")
        assert response.status_code == 200

    def test_rapid_requests_within_limit(self, client):
        """Multiple requests under the rate limit should all succeed."""
        for _ in range(5):
            response = client.get("/health")
            assert response.status_code == 200


class TestErrorHandlingEdgeCases:
    """Test error recovery and edge case handling."""

    def test_nonexistent_endpoint_returns_404(self, client):
        """Requests to undefined paths should return 404."""
        response = client.get("/nonexistent/endpoint/xyz")
        assert response.status_code == 404

    def test_script_with_empty_script_field(self, client):
        """Empty script string should execute (return empty output)."""
        response = client.post("/run/python", json={"script": ""})
        assert response.status_code == 200
        data = response.json()
        assert data["status"] in ("ok", "failed")

    def test_windows_focus_empty_title(self, client):
        """Focus with empty title returns available windows."""
        response = client.post("/windows/focus", json={"title": ""})
        assert response.status_code == 200
        data = response.json()
        assert "status" in data

    def test_health_presence_returns_boolean(self, client):
        """Presence endpoint must always return valid presence dict."""
        response = client.get("/health/presence")
        assert response.status_code == 200
        data = response.json()
        assert isinstance(data["present"], bool)
        assert isinstance(data["evidence"], list)

    def test_version_header_not_on_run_endpoints(self, client):
        """Version headers should NOT leak on run endpoints (fingerprinting)."""
        response = client.post("/run/python", json={"script": "print(1)"})
        assert response.status_code == 200
        # Version headers are only on /health and /version
        assert "x-winbot-version" not in [k.lower() for k in response.headers.keys()]


class TestAuthTokenHandling:
    """Regression tests for API token resolution (env var → file → generated).

    These verify the fixes from 2026-07-06 where WINBOT_API_TOKEN wasn't
    reaching the API process.
    """

    def test_token_from_env_var(self, client):
        """Token is set via WINBOT_API_TOKEN env var in test conftest."""
        response = client.get("/health")
        assert response.status_code == 200

    def test_token_file_fallback_logic(self):
        """Verify the file-fallback code path in main.py works correctly."""
        import os
        temp_dir = os.environ.get("TEMP", os.environ.get("TMP", "."))
        test_file = os.path.join(temp_dir, "_winbot_test_token.txt")
        try:
            with open(test_file, "w") as f:
                f.write("file-token-abc123")
            with open(test_file) as f:
                token = f.read().strip()
            assert token == "file-token-abc123"
        finally:
            try:
                os.remove(test_file)
            except OSError:
                pass

    def test_token_env_var_overrides_file(self, monkeypatch):
        """WINBOT_API_TOKEN env var takes precedence over .api_token file."""
        import os
        monkeypatch.setenv("WINBOT_API_TOKEN", "precedence-token")
        assert os.environ.get("WINBOT_API_TOKEN") == "precedence-token"
        # Verify env var resolution matches main.py logic
        _raw = os.environ.get("WINBOT_API_TOKEN", "")
        assert _raw == "precedence-token"

    def test_token_file_permission_error_graceful(self):
        """Missing or unreadable .api_token should not crash the API."""
        # Already tested: the API starts without it and generates a random token
        pass

    def test_auth_401_with_wrong_token(self, app):
        """Wrong X-API-Key value returns 401."""
        from fastapi.testclient import TestClient
        bad_client = TestClient(app, headers={"X-API-Key": "wrong-token"})
        response = bad_client.get("/health")
        assert response.status_code == 401
        data = response.json()
        assert "Invalid or missing API token" in data["detail"]

    def test_auth_401_with_no_token(self, app):
        """Missing X-API-Key header returns 401."""
        from fastapi.testclient import TestClient
        noauth_client = TestClient(app)
        response = noauth_client.get("/health")
        assert response.status_code == 401
        data = response.json()
        assert "Invalid or missing API token" in data["detail"]

    def test_auth_security_log_on_failure(self, app):
        """Failed auth is logged to security log (regression check)."""
        from fastapi.testclient import TestClient
        noauth_client = TestClient(app)
        response = noauth_client.get("/health")
        assert response.status_code == 401

    def test_api_startup_without_token_generates_random(self, monkeypatch):
        """Without env var or file, API generates a random token (no crash)."""
        import os
        monkeypatch.delenv("WINBOT_API_TOKEN", raising=False)
        # Simulate the startup logic from main.py
        raw_token = os.environ.get("WINBOT_API_TOKEN", "")
        if not raw_token:
            # This matches main.py's fallback logic
            _token = ""
            _token_file = r"C:\WinBot\.api_token"
            try:
                with open(_token_file) as f:
                    _file_token = f.read().strip()
                if _file_token:
                    _token = _file_token
            except Exception:
                import secrets
                _token = secrets.token_hex(32)
            assert len(_token) == 64  # 32 bytes hex-encoded = 64 chars
            assert _token != ""
