import argparse
import contextlib
import importlib.util
import io
import unittest
from pathlib import Path
from unittest.mock import patch


SCRIPT = Path(__file__).resolve().parents[1] / "scripts" / "jules.py"
SPEC = importlib.util.spec_from_file_location("jules", SCRIPT)
jules = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(jules)


class PublicSourcePreflightTest(unittest.TestCase):
    def setUp(self):
        self.args = argparse.Namespace(repository="SemperSupra/truenas-app-foundry", branch="main")

    def test_public_exact_source_passes_without_listing_other_sources(self):
        sources = [
            {"githubRepo": {"owner": "Someone", "repo": "private", "isPrivate": True}},
            {"githubRepo": {"owner": "SemperSupra", "repo": "truenas-app-foundry", "isPrivate": False,
                            "branches": [{"displayName": "main"}]}},
        ]
        out = io.StringIO()
        with patch.object(jules, "list_sources", return_value=sources), contextlib.redirect_stdout(out):
            jules.preflight_public_source(self.args)
        self.assertIn('"eligible": true', out.getvalue())
        self.assertNotIn("Someone", out.getvalue())

    def test_private_or_missing_branch_fails_closed(self):
        for private, branches in ((True, [{"displayName": "main"}]),
                                  (False, [{"displayName": "other"}]),
                                  (None, [{"displayName": "main"}])):
            with self.subTest(private=private, branches=branches):
                source = {"githubRepo": {"owner": "SemperSupra", "repo": "truenas-app-foundry",
                                         "isPrivate": private, "branches": branches}}
                with patch.object(jules, "list_sources", return_value=[source]):
                    with self.assertRaises(SystemExit):
                        jules.preflight_public_source(self.args)


if __name__ == "__main__":
    unittest.main()
