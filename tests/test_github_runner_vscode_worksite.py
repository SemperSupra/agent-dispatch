from __future__ import annotations

import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


class GitHubRunnerVSCodeWorksiteContractTests(unittest.TestCase):
    def test_preflight_is_credential_free(self) -> None:
        text = (
            ROOT / "scripts" / "github_runner_vscode_worksite_preflight.sh"
        ).read_text(encoding="utf-8")

        self.assertIn("user login --help", text)
        self.assertIn("interactive_login_attempted=false", text)
        self.assertIn("credential_material_recorded=false", text)
        self.assertNotIn("VSCODE_CLI_ACCESS_TOKEN", text)
        self.assertNotIn("GITHUB_TOKEN", text)
        self.assertNotIn("device_code", text)

    def test_preflight_observes_required_tunnel_capabilities(self) -> None:
        text = (
            ROOT / "scripts" / "github_runner_vscode_worksite_preflight.sh"
        ).read_text(encoding="utf-8")

        for expected in (
            "login_access_token_flag",
            "login_refresh_token_flag",
            "tunnel_name_flag",
            "tunnel_no_sleep_flag",
            "tunnel_accept_license_flag",
            "tunnel_install_extension_flag",
            "tunnel_status_json_present",
            "tunnel_status_no_running",
            "tunnel_status_service_installed",
            "vscode_dev_http_status",
            "relay_http_status",
        ):
            self.assertIn(expected, text)

    def test_preflight_requires_clean_structured_tunnel_status(self) -> None:
        text = (
            ROOT / "scripts" / "github_runner_vscode_worksite_preflight.sh"
        ).read_text(encoding="utf-8")

        self.assertIn("code tunnel --cli-data-dir", text)
        self.assertIn("status_json_present", text)
        self.assertIn("status_no_running", text)
        self.assertIn("status_service_installed", text)
        self.assertIn('"status_json_present" != true', text)
        self.assertIn('"status_no_running" != true', text)
        self.assertIn('"status_service_installed" != false', text)

    def test_workflow_is_public_safe_and_secret_free(self) -> None:
        text = (
            ROOT
            / ".github"
            / "workflows"
            / "github-runner-vscode-worksite-preflight.yml"
        ).read_text(encoding="utf-8")

        self.assertIn("permissions:\n  contents: read", text)
        self.assertIn("pull_request:", text)
        self.assertIn("workflow_dispatch:", text)
        self.assertNotIn("pull_request_target:", text)
        self.assertNotIn("secrets.", text)
        self.assertNotIn("personal-ops", text)
        self.assertIn("persist-credentials: false", text)

    def test_workflow_runs_real_preflight_after_contract(self) -> None:
        text = (
            ROOT
            / ".github"
            / "workflows"
            / "github-runner-vscode-worksite-preflight.yml"
        ).read_text(encoding="utf-8")

        self.assertIn("needs: contract", text)
        self.assertIn("github_runner_vscode_worksite_preflight.sh", text)
        self.assertIn("upload-artifact@", text)
        self.assertIn("Observe receipt presence", text)
        self.assertNotIn("hashFiles(", text)


if __name__ == "__main__":
    unittest.main()
