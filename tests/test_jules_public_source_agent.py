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

    def test_native_session_reuse_fails_closed_on_ambiguity_or_source_drift(self):
        title = "sidecar:workset:delegation:assignment"
        session = {"title": title, "id": "safe-id", "sourceContext": {
            "source": "sources/public", "githubRepoContext": {"startingBranch": "main"}}}
        with patch.object(agent, "pages", return_value=[session]):
            self.assertEqual(agent.matching_session(title, "sources/public", "main"), session)
            with self.assertRaises(ValueError):
                agent.matching_session(title, "sources/private", "main")
        with patch.object(agent, "pages", return_value=[session, session]):
            with self.assertRaises(ValueError):
                agent.matching_session(title, "sources/public", "main")

    def test_completed_result_needs_agent_message(self):
        with patch.object(agent, "pages", return_value=[{"sessionCompleted": {}}]):
            with self.assertRaises(ValueError):
                agent.final_message("safe-id")
        activities = [
            {"createTime": "2026-01-01T00:00:00Z", "agentMessaged": {"agentMessage": "old"}},
            {"createTime": "2026-01-01T00:01:00Z", "agentMessaged": {"agentMessage": "final"}},
        ]
        with patch.object(agent, "pages", return_value=activities):
            self.assertEqual(agent.final_message("safe-id"), "final")


if __name__ == "__main__":
    unittest.main()
