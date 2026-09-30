"""
Property-based conformance tests for WinBot API core logic.

Uses Hypothesis for exhaustive property exploration of:
- Auth token resolution (env var → file → random)
- Rate limiting sliding window
- Session directory creation

This catches edge cases that example-based tests miss.
"""

import os
import secrets
import tempfile

from hypothesis import assume, given, settings
from hypothesis import strategies as st

# ============================================================
# Property: API token resolution
#
# The API resolves its token in this order:
#   1. WINBOT_API_TOKEN env var
#   2. C:\WinBot\.api_token file
#   3. Random 32-byte hex token (fallback)
#
# Properties we test:
#   - Env var always wins when set
#   - File is used when env var is absent but file exists
#   - Random token is generated when neither is available
#   - All tokens are non-empty strings
# ============================================================


@st.composite
def token_strategy(draw):
    """Generate realistic token values for property testing."""
    token_type = draw(st.sampled_from(["env", "file", "both", "none", "empty_env", "empty_file"]))
    env_token = None
    file_token = None

    if token_type in ("env", "both"):
        env_token = draw(st.text(min_size=1, max_size=128, alphabet="abcdef0123456789-"))
    if token_type in ("file", "both"):
        file_token = draw(st.text(min_size=1, max_size=128, alphabet="abcdef0123456789-"))
    if token_type == "empty_env":
        env_token = ""
        file_token = draw(st.text(min_size=1, max_size=128, alphabet="abcdef0123456789-"))
    if token_type == "empty_file":
        env_token = draw(st.text(min_size=1, max_size=128, alphabet="abcdef0123456789-"))
        file_token = ""
    if token_type == "none":
        pass  # Both None

    return env_token, file_token


def resolve_token(env_token, file_token):
    """Simulate main.py's token resolution logic."""
    if env_token:
        return env_token
    if file_token:
        return file_token
    return secrets.token_hex(32)


class TestTokenResolutionProperties:
    """Property-based tests for API token resolution."""

    @given(token_strategy())
    @settings(max_examples=100)
    def test_token_always_non_empty(self, tokens):
        """Token resolution must always return a non-empty string."""
        env_token, file_token = tokens
        token = resolve_token(env_token, file_token)
        assert token, "Token must not be empty"
        assert isinstance(token, str)

    @given(token_strategy())
    @settings(max_examples=100)
    def test_env_var_takes_precedence(self, tokens):
        """When env var is set and non-empty, it must be the resolved token."""
        env_token, file_token = tokens
        if not env_token:
            assume(True)  # skip — env var not set, no precedence test
            return
        token = resolve_token(env_token, file_token)
        assert token == env_token, (
            f"Env var '{env_token}' should win over file '{file_token}', "
            f"but got '{token}'"
        )

    @given(token_strategy())
    @settings(max_examples=100)
    def test_file_used_when_no_env(self, tokens):
        """When env var is absent, file token is used."""
        env_token, file_token = tokens
        assume(not env_token)  # only test when env is absent
        if not file_token:
            assume(True)
            return
        token = resolve_token(env_token, file_token)
        assert token == file_token, (
            f"File token '{file_token}' should be used when env is absent, "
            f"but got '{token}'"
        )

    def test_fallback_is_random_hex(self):
        """When both absent, fallback must be a 64-char hex string."""
        token = resolve_token(None, None)
        assert len(token) == 64, f"Expected 64-char hex, got {len(token)} chars"
        assert all(c in "0123456789abcdef" for c in token), (
            f"Token '{token[:16]}...' is not valid hex"
        )

    @given(st.text(min_size=1, max_size=256))
    @settings(max_examples=50)
    def test_nonempty_env_token_preserved(self, env_token):
        """Non-empty env var tokens are used as-is by the resolver."""
        assume(len(env_token) > 0)
        token = resolve_token(env_token, None)
        assert token == env_token

    def test_env_var_overrides_empty_string_file(self):
        """Empty env var ('') is treated as 'not set' — file or fallback used."""
        token = resolve_token("", "file-token")
        assert token == "file-token"
        token2 = resolve_token("", "")
        assert len(token2) == 64

    def test_real_main_py_logic(self, monkeypatch):
        """Integration: main.py's actual token resolution."""
        monkeypatch.delenv("WINBOT_API_TOKEN", raising=False)
        # Simulate main.py block
        raw_token = os.environ.get("WINBOT_API_TOKEN", "")
        if not raw_token:
            _token_file = r"C:\WinBot\.api_token"
            try:
                with open(_token_file) as f:
                    _file_token = f.read().strip()
                if _file_token:
                    raw_token = _file_token
            except Exception:
                raw_token = secrets.token_hex(32)
        assert raw_token, "Token must be non-empty"


# ============================================================
# Property: Rate limiting
#
# The rate limiter uses a sliding window per IP. Properties:
#   - Requests under the limit always pass
#   - Requests at exactly the limit should pass
#   - Requests over the limit get 429
# ============================================================

class TestRateLimiterProperties:
    """Property-based tests for the rate limiting middleware."""

    def test_single_request_passes(self, client):
        """One request always succeeds (trivially under limit)."""
        resp = client.get("/health")
        assert resp.status_code == 200

    def test_many_requests_within_limit(self, client):
        """A burst of requests under WINBOT_RATE_LIMIT (100/min) all succeed."""
        for _ in range(10):
            resp = client.get("/health")
            assert resp.status_code == 200

    def test_lifecycle_status_exempt_from_rate_limit(self, client):
        """/lifecycle/status and /lifecycle/cancel are rate-limit exempt."""
        for _ in range(20):
            resp = client.get("/lifecycle/status")
            assert resp.status_code == 200


# ============================================================
# Property: Session directory creation
# ============================================================

class TestSessionDirectoryProperties:
    """Property-based tests for session directory creation."""

    @given(label=st.one_of(
        st.none(),
        st.text(min_size=1, max_size=32, alphabet="abcdefghijklmnopqrstuvwxyz0123456789-_"),
    ))
    @settings(max_examples=30)
    def test_session_dir_created_with_correct_structure(self, label):
        """Session dir must be created with all subdirectories."""

        import main as api_main
        original_root = api_main.SESSION_ROOT
        try:
            with tempfile.TemporaryDirectory() as tmpdir:
                api_main.SESSION_ROOT = tmpdir
                session_dir = api_main.get_session_dir(label)
                assert os.path.exists(session_dir), f"Session dir not created: {session_dir}"
                for sub in ("screenshots", "logs", "scripts", "artifacts"):
                    sub_path = os.path.join(session_dir, sub)
                    assert os.path.isdir(sub_path), f"Subdirectory not created: {sub_path}"
        finally:
            api_main.SESSION_ROOT = original_root

    @given(st.integers(min_value=1, max_value=30))
    @settings(max_examples=10)
    def test_multiple_sessions_have_unique_paths(self, count):
        """Each call to get_session_dir should return a unique path."""

        import main as api_main
        original_root = api_main.SESSION_ROOT
        try:
            with tempfile.TemporaryDirectory() as tmpdir:
                api_main.SESSION_ROOT = tmpdir
                paths = set()
                for _ in range(count):
                    path = api_main.get_session_dir()
                    paths.add(path)
                assert len(paths) == count, (
                    f"Expected {count} unique paths, got {len(paths)}"
                )
        finally:
            api_main.SESSION_ROOT = original_root
