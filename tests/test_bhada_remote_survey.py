import json
import tempfile
import unittest
from datetime import datetime, timezone
from pathlib import Path

from scripts.bhada_remote_survey import choose_profile, load_config, sanitize


class RemoteSurveyTests(unittest.TestCase):
    def test_auto_profile_alternates_by_week(self):
        broad = datetime.fromisocalendar(2026, 40, 7).replace(tzinfo=timezone.utc)
        core = datetime.fromisocalendar(2026, 41, 7).replace(tzinfo=timezone.utc)
        self.assertEqual(choose_profile("auto", broad), "broad")
        self.assertEqual(choose_profile("auto", core), "core")
        self.assertEqual(choose_profile("core", broad), "core")

    def test_config_has_core_and_broad_profiles(self):
        config = load_config(Path("surveys/bhada/standing-survey.json"))
        self.assertTrue(config["profiles"]["core"]["providers"])
        self.assertGreaterEqual(
            len(config["profiles"]["broad"]["providers"]),
            len(config["profiles"]["core"]["providers"]),
        )

    def test_sanitizer_preserves_status_but_drops_sensitive_detail(self):
        raw = {
            "providers": [
                {
                    "provider": "miruro",
                    "status": "operational",
                    "anime_url": "https://private-detail.invalid/title",
                    "candidate_errors": ["secret-ish raw diagnostic"],
                    "stages": {
                        "search": {"status": "WORKING", "result_count": 3},
                        "metadata": {"status": "WORKING", "provider": "miruro"},
                        "episodes": {"status": "WORKING", "sample_count": 1},
                        "resolve": {
                            "status": "FAILED",
                            "reason": "https://signed.example/path?token=secret",
                        },
                    },
                }
            ]
        }
        receipt = sanitize(
            raw,
            assignment_id="survey-001",
            profile="core",
            observed_at="2026-09-26T03:17:00Z",
            source_revision="abc123",
            workflow_run_id="42",
        )
        encoded = json.dumps(receipt)
        self.assertIn("miruro", encoded)
        self.assertIn("FAILED", encoded)
        self.assertNotIn("signed.example", encoded)
        self.assertNotIn("private-detail", encoded)
        self.assertNotIn("candidate_errors", encoded)
        self.assertEqual(receipt["execution"]["local_sovereign_required"], False)

    def test_sanitizer_rejects_missing_provider_array(self):
        with self.assertRaises(ValueError):
            sanitize(
                {},
                assignment_id="survey-001",
                profile="core",
                observed_at="2026-09-26T03:17:00Z",
                source_revision="abc123",
                workflow_run_id="42",
            )


if __name__ == "__main__":
    unittest.main()
