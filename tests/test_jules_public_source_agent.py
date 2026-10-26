import importlib.util
import sys
import unittest
from pathlib import Path
from unittest.mock import patch


SCRIPTS = Path(__file__).resolve().parents[1] / "scripts"
sys.path.insert(0, str(SCRIPTS))
SPEC = importlib.util.spec_from_file_location("jules_public_source_agent", SCRIPTS / "jules_public_source_agent.py")
agent = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(agent)


class PublicSourceAgentBoundaryTest(unittest.TestCase):
    def test_assignment_requires_exact_registered_triple(self):
        good = agent.approved_assignment("foliorelay-keycloak-source-audit-20261024",
                                         "keycloak-catalog-source-audit", "foliorelay-keycloak-audit-001")
        self.assertEqual(good["repository"], "SemperSupra/truenas-app-foundry")
        for workset, delegation, assignment in (
            ("other", "keycloak-catalog-source-audit", "foliorelay-keycloak-audit-001"),
            ("foliorelay-keycloak-source-audit-20261024", "other", "foliorelay-keycloak-audit-001"),
            ("foliorelay-keycloak-source-audit-20261024", "keycloak-catalog-source-audit", "other"),
        ):
            with self.subTest(assignment=assignment, workset=workset, delegation=delegation):
                with self.assertRaises(ValueError):
                    agent.approved_assignment(workset, delegation, assignment)

    def test_native_session_reuse_fails_closed(self):
        title = "sidecar:workset:delegation:assignment"
        session = {"title": title, "id": "safe-id", "sourceContext": {
            "source": "sources/public", "githubRepoContext": {"startingBranch": "main"}}}
        with patch.object(agent, "pages", return_value=[session]):
            with self.assertRaises(ValueError):
                agent.reject_existing_session(title)
        with patch.object(agent, "pages", return_value=[session, session]):
            with self.assertRaises(ValueError):
                agent.reject_existing_session(title)
        with patch.object(agent, "pages", return_value=[]):
            agent.reject_existing_session(title)

    def test_completed_result_needs_agent_message(self):
        with patch.object(agent, "pages", return_value=[{"sessionCompleted": {}}]):
            with self.assertRaises(ValueError):
                agent.final_message("safe-id")
        activities = [
            {"createTime": "2026-01-01T00:00:00Z", "agentMessaged": {"agentMessage": "old"}},
            {"createTime": "2026-01-01T00:01:00Z", "agentMessaged": {"agentMessage": "# Evidence\na\n# Conclusion\nb\n# Falsification test\nc\n# Remaining unknowns\nd\n# Next gate\ne"}},
        ]
        with patch.object(agent, "pages", return_value=activities):
            self.assertIn("# Next gate", agent.final_message("safe-id"))
            self.assertTrue(agent.structured_finding(agent.final_message("safe-id")))
        self.assertFalse(agent.structured_finding("**Evidence**\nunsupported claim"))

    def test_sealed_plaintext_budget_includes_wrapper_and_utf8(self):
        # The trusted private pickup rejects decrypted findings over 1 MiB.
        # The 43-byte wrapper must be counted BEFORE the age artifact is made.
        overhead = len(agent.SEALED_FINDING_PREFIX.encode("utf-8")) + len("\n".encode())
        capacity = agent.MAX_SEALED_PLAINTEXT_BYTES - overhead
        self.assertEqual(overhead, 43)
        self.assertEqual(len(agent.sealed_finding_plaintext("A" * capacity)),
                         agent.MAX_SEALED_PLAINTEXT_BYTES)
        with self.assertRaisesRegex(ValueError, "wrapped native finding exceeds"):
            agent.sealed_finding_plaintext("A" * (capacity + 1))

        # Non-ASCII characters are measured as UTF-8 bytes, not code points.
        multilingual = "ก" * (capacity // 3) + "A" * (capacity % 3)
        self.assertEqual(len(agent.sealed_finding_plaintext(multilingual)),
                         agent.MAX_SEALED_PLAINTEXT_BYTES)
        with self.assertRaisesRegex(ValueError, "wrapped native finding exceeds"):
            agent.sealed_finding_plaintext(multilingual + "A")

    def test_prior_workflow_attempt_consumes_assignment(self):
        import io
        current = b'{"workflow_runs":[{"id":42,"display_title":"sidecar:w:d:a"}]}'
        prior = b'{"workflow_runs":[{"id":41,"display_title":"sidecar:w:d:a"},{"id":42,"display_title":"sidecar:w:d:a"}]}'
        env = {"GITHUB_TOKEN": "test", "GITHUB_REPOSITORY": "SemperSupra/agent-dispatch",
               "GITHUB_RUN_ID": "42", "GITHUB_RUN_ATTEMPT": "1"}
        with patch.dict(agent.os.environ, env), patch.object(agent.urllib.request, "urlopen", return_value=io.BytesIO(current)):
            agent.reject_prior_workflow_run("sidecar:w:d:a")
        with patch.dict(agent.os.environ, env), patch.object(agent.urllib.request, "urlopen", return_value=io.BytesIO(prior)):
            with self.assertRaises(ValueError):
                agent.reject_prior_workflow_run("sidecar:w:d:a")

    def test_execute_completed_result_needs_sealing_and_remains_unreviewed(self):
        entry = agent.APPROVED["foliorelay-keycloak-audit-001"]
        recipient = "age1" + "q" * 58
        response = {"id": "safe-id", "state": "COMPLETED"}
        with patch.object(agent, "approved_assignment", return_value=entry), \
             patch.object(agent, "task_text", return_value="prompt"), \
             patch.object(agent.jules, "preflight_public_source"), \
             patch.object(agent.jules, "resolve_source", return_value={"name": "sources/public"}), \
             patch.object(agent, "reject_prior_workflow_run"), \
             patch.object(agent, "reject_existing_session"), \
             patch.object(agent.jules, "request", return_value=response) as request, \
             patch.object(agent, "final_message", return_value="# Evidence\na\n# Conclusion\nb\n# Falsification test\nc\n# Remaining unknowns\nd\n# Next gate\ne"), \
             patch.object(agent, "seal_finding", return_value=("f" * 64, 99)) as seal, \
             patch.object(agent, "write_receipt") as receipt:
            result = agent.execute(entry["workset_id"], entry["delegation_id"],
                                   "foliorelay-keycloak-audit-001", recipient)
        self.assertEqual(result["independent_acceptance"], "not-run")
        self.assertEqual(request.call_args_list[0].args[:2], ("POST", "/sessions"))
        self.assertEqual(request.call_args_list[1].args[:2], ("GET", "/sessions/safe-id"))
        seal.assert_called_once()
        self.assertEqual(receipt.call_args_list[-1].kwargs["sealed_sha256"], "f" * 64)

    def test_execute_rejects_prior_attempt_before_provider_post(self):
        entry = agent.APPROVED["foliorelay-keycloak-audit-001"]
        with patch.object(agent, "task_text", return_value="prompt"), \
             patch.object(agent.jules, "preflight_public_source"), \
             patch.object(agent.jules, "resolve_source", return_value={"name": "sources/public"}), \
             patch.object(agent, "reject_prior_workflow_run", side_effect=ValueError("prior attempt")), \
             patch.object(agent.jules, "request") as request:
            with self.assertRaises(ValueError):
                agent.execute(entry["workset_id"], entry["delegation_id"],
                              "foliorelay-keycloak-audit-001", "age1" + "q" * 58)
        request.assert_not_called()

    def test_unstructured_completed_message_is_sealed_before_failure(self):
        entry = agent.APPROVED["foliorelay-keycloak-audit-001"]
        with patch.object(agent, "task_text", return_value="prompt"), \
             patch.object(agent.jules, "preflight_public_source"), \
             patch.object(agent.jules, "resolve_source", return_value={"name": "sources/public"}), \
             patch.object(agent, "reject_prior_workflow_run"), \
             patch.object(agent, "reject_existing_session"), \
             patch.object(agent.jules, "request", return_value={"id": "safe-id", "state": "COMPLETED"}), \
             patch.object(agent, "final_message", return_value="**Evidence**\nclaim"), \
             patch.object(agent, "seal_finding", return_value=("f" * 64, 99)) as seal, \
             patch.object(agent, "write_receipt") as receipt:
            with self.assertRaisesRegex(ValueError, "sealed result requires private review"):
                agent.execute(entry["workset_id"], entry["delegation_id"],
                              "foliorelay-keycloak-audit-001", "age1" + "q" * 58)
        seal.assert_called_once()
        self.assertEqual(receipt.call_args_list[-1].kwargs["status"], "provider-completed-unstructured")
        self.assertEqual(receipt.call_args_list[-1].kwargs["independent_acceptance"], "not-run")


if __name__ == "__main__":
    unittest.main()
