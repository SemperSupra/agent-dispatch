import os
import sys
import unittest
from pathlib import Path
from unittest.mock import patch


ROOT = Path(__file__).resolve().parents[1]
SCRIPTS = ROOT / "scripts"
sys.path.insert(0, str(SCRIPTS))

import jules  # noqa: E402
import jules_preflight  # noqa: E402


class JulesPreflightTests(unittest.TestCase):
    def test_preflight_returns_only_sanitized_readiness(self):
        private_repo = "private-owner/secret-repository"
        private_branch = "secret-branch"
        private_source = {"name": "sources/secret-provider-id", "githubRepo": {"owner": "private-owner", "repo": "secret-repository"}}

        with (
            patch.object(jules_preflight, "resolve_target", return_value=(private_repo, private_branch)),
            patch.object(jules_preflight, "load_task", return_value="PRIVATE PROMPT CONTENT"),
            patch.object(jules_preflight, "resolve_source", return_value=private_source),
        ):
            result = jules_preflight.preflight("opaque-target", "approved-task")

        self.assertEqual(
            result,
            {
                "ready": True,
                "target": "opaque-target",
                "task": "approved-task",
                "target_policy": "approved",
                "task_policy": "approved",
                "jules_source": "available-unique",
                "session_created": False,
                "authority_mutation": False,
            },
        )
        rendered = repr(result)
        self.assertNotIn(private_repo, rendered)
        self.assertNotIn(private_branch, rendered)
        self.assertNotIn("secret-provider-id", rendered)
        self.assertNotIn("PRIVATE PROMPT CONTENT", rendered)

    def test_preflight_does_not_call_provider_session_creation(self):
        with (
            patch.object(jules_preflight, "resolve_target", return_value=("owner/repo", "main")),
            patch.object(jules_preflight, "load_task", return_value="task"),
            patch.object(jules_preflight, "resolve_source", return_value={"name": "sources/1"}),
            patch.object(jules, "request") as provider_request,
        ):
            result = jules_preflight.preflight("opaque-target", "approved-task")

        self.assertTrue(result["ready"])
        provider_request.assert_not_called()

    def test_real_target_policy_rejects_unapproved_alias_without_disclosure(self):
        old = os.environ.get("JULES_TARGETS_JSON")
        os.environ["JULES_TARGETS_JSON"] = '{"approved":{"repository":"owner/private","branch":"main"}}'
        try:
            with self.assertRaises(SystemExit) as raised:
                jules.resolve_target("not-approved")
            self.assertEqual(str(raised.exception), "Target is not approved")
            self.assertNotIn("owner/private", str(raised.exception))
        finally:
            if old is None:
                os.environ.pop("JULES_TARGETS_JSON", None)
            else:
                os.environ["JULES_TARGETS_JSON"] = old


if __name__ == "__main__":
    unittest.main()
