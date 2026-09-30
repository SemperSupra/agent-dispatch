"""
WinBot Config Validation Tests
Verifies config.json integrity: required keys, valid value ranges,
and runtime constraint enforcement.
"""

import json
import os
import tempfile

import pytest

# ============================================================
# Config schema — what a valid config MUST contain
# ============================================================
REQUIRED_TOP_KEYS = {"master", "clones", "credentials", "api", "sessions"}

REQUIRED_MASTER_KEYS = {
    "vmName": str,
    "vhdxPath": str,
    "vmPath": str,
    "memoryBytes": int,
    "processors": int,
    "generation": int,
    "switchName": str,
}

REQUIRED_CLONES_KEYS = {
    "basePath": str,
    "defaultMemoryBytes": int,
    "defaultProcessors": int,
}

REQUIRED_API_KEYS = {
    "port": int,
    "token": str,
    "healthCheckTimeoutSeconds": int,
    "healthCheckIntervalSeconds": int,
}


class TestConfigSchema:
    """Verify config.json structure and value constraints."""

    def test_config_file_is_valid_json(self):
        """config.json must be valid JSON."""
        config_path = _config_file_path()
        if not os.path.exists(config_path):
            pytest.skip(f"config.json not found at {config_path}")
        try:
            with open(config_path, encoding="utf-8-sig") as f:
                json.load(f)
        except json.JSONDecodeError as e:
            pytest.fail(f"config.json is not valid JSON: {e}")

    def test_required_top_level_keys(self):
        """Config must have all required top-level sections."""
        config = _load_config()
        missing = REQUIRED_TOP_KEYS - set(config.keys())
        assert not missing, f"Missing top-level keys in config.json: {missing}"

    def test_master_section_has_required_keys(self):
        """master section must have all required keys."""
        config = _load_config()
        master = config.get("master", {})
        for key, expected_type in REQUIRED_MASTER_KEYS.items():
            assert key in master, f"master.{key} is missing"
            assert isinstance(master[key], expected_type), (
                f"master.{key} should be {expected_type.__name__}, "
                f"got {type(master[key]).__name__}"
            )

    def test_clones_section_has_required_keys(self):
        """clones section must have all required keys."""
        config = _load_config()
        clones = config.get("clones", {})
        for key, expected_type in REQUIRED_CLONES_KEYS.items():
            assert key in clones, f"clones.{key} is missing"
            assert isinstance(clones[key], expected_type), (
                f"clones.{key} should be {expected_type.__name__}"
            )

    def test_api_section_has_required_keys(self):
        """api section must have all required keys."""
        config = _load_config()
        api = config.get("api", {})
        for key, expected_type in REQUIRED_API_KEYS.items():
            assert key in api, f"api.{key} is missing"
            assert isinstance(api[key], expected_type), (
                f"api.{key} should be {expected_type.__name__}"
            )


class TestConfigValueConstraints:
    """Verify config values are within valid ranges."""

    def test_api_port_is_valid(self):
        """port must be between 1 and 65535."""
        config = _load_config()
        port = config["api"]["port"]
        assert 1 <= port <= 65535, f"api.port={port} is out of range (1-65535)"

    def test_memory_values_are_positive(self):
        """All memory byte values must be > 0."""
        config = _load_config()
        assert config["master"]["memoryBytes"] > 0, (
            "master.memoryBytes must be positive"
        )
        assert config["clones"]["defaultMemoryBytes"] > 0, (
            "clones.defaultMemoryBytes must be positive"
        )

    def test_processor_counts_are_positive(self):
        """Processor counts must be >= 1."""
        config = _load_config()
        assert config["master"]["processors"] >= 1, "master.processors must be >= 1"
        assert config["clones"]["defaultProcessors"] >= 1, "clones.defaultProcessors must be >= 1"

    def test_generation_is_1_or_2(self):
        """Hyper-V generation must be 1 or 2."""
        config = _load_config()
        gen = config["master"]["generation"]
        assert gen in (1, 2), f"master.generation={gen} must be 1 or 2"

    def test_health_check_timeouts_are_positive(self):
        """Health check timeouts must be > 0."""
        config = _load_config()
        assert config["api"]["healthCheckTimeoutSeconds"] > 0
        assert config["api"]["healthCheckIntervalSeconds"] > 0

    def test_paths_are_non_empty_strings(self):
        """All path values must be non-empty strings."""
        config = _load_config()
        path_keys = [
            ("master", "vhdxPath"),
            ("master", "vmPath"),
            ("master", "switchName"),
            ("clones", "basePath"),
            ("sessions", "basePath"),
        ]
        for section, key in path_keys:
            value = config.get(section, {}).get(key, "")
            assert isinstance(value, str) and value.strip(), (
                f"{section}.{key} is empty or not a string"
            )


class TestConfigDefaults:
    """Verify module applies defaults correctly when keys are missing."""

    def test_defaults_are_applied_for_empty_api(self):
        """Empty api section should get default port, timeouts."""
        import sys
        # Ensure project root is on path for host.WinBotMCP import
        project_root = os.path.dirname(os.path.dirname(
            os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))
        if project_root not in sys.path:
            sys.path.insert(0, project_root)

        from host.WinBotMCP.discovery import load_config

        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
            json.dump({
                "master": {
                    "vmName": "Test", "vhdxPath": "C:\\test.vhdx",
                    "vmPath": "C:\\test\\", "memoryBytes": 4*1024**3,
                    "processors": 4, "generation": 2, "switchName": "Default"
                },
                "clones": {
                    "basePath": "C:\\clones\\", "defaultMemoryBytes": 4*1024**3,
                    "defaultProcessors": 2
                },
                "credentials": {"vmUsername": "test"},
                "api": {},
                "sessions": {"basePath": "C:\\sessions\\"},
            }, f)
            tmp_path = f.name

        try:
            config = load_config(tmp_path)
            assert config["api"]["port"] == 8000
            assert config["api"]["healthCheckTimeoutSeconds"] == 120
            assert config["api"]["healthCheckIntervalSeconds"] == 5
        finally:
            os.unlink(tmp_path)


def _config_file_path():
    """Return the absolute path to config.json."""
    test_dir = os.path.dirname(os.path.abspath(__file__))  # guest/api/tests/
    api_dir = os.path.dirname(test_dir)                     # guest/api/
    guest_dir = os.path.dirname(api_dir)                    # guest/
    project_dir = os.path.dirname(guest_dir)                # project root = WinBot/
    return os.path.join(project_dir, "config.json")


def _load_config():
    """Load the real config.json for schema validation."""
    config_path = _config_file_path()
    if not os.path.exists(config_path):
        pytest.skip(f"config.json not found at {config_path}")
    with open(config_path, encoding="utf-8-sig") as f:
        return json.load(f)
