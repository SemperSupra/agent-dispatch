"""Negative-first qualification of the public PR-event request boundary."""
from __future__ import annotations

from contextlib import contextmanager
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
import gha_pr_request as pr

BASE = "a" * 40
HEAD = "b" * 40
MERGE = "c" * 40
FILE = "requests/gha/pr-cpu-contract-one.json"


def manifest():
    return {"schema": "gha-workload-request/v1", "assignment_id": "pr-cpu-contract-one",
            "runner": "ubuntu-24.04", "workload": "arithmetic-oracle",
            "timeout_seconds": 30, "data_class": "public-synthetic",
            "max_attempts": 1, "max_cost_usd": 0}


def event():
    return {"action": "opened",
            "pull_request": {"head": {"sha": HEAD, "repo": {"full_name": "Public/fixture"}},
                             "base": {"sha": BASE, "repo": {"full_name": "Public/fixture"}}}}


@contextmanager
def candidate(*, changed=(FILE,), added=(FILE,), payload=None, git_overrides=None):
    with tempfile.TemporaryDirectory() as td:
        root = Path(td)
        file = root / FILE
        file.parent.mkdir(parents=True)
        file.write_bytes(json.dumps(manifest() if payload is None else payload).encode() + b"\n")
        responses = {"HEAD": MERGE, "HEAD^1": BASE, "HEAD^2": HEAD,
                     "DIFF_CHANGED": "\0".join(changed) + "\0",
                     "DIFF_ADDED": "\0".join(added) + "\0"}
        responses.update(git_overrides or {})
        def git(*argv):
            if argv[0] == "rev-parse":
                return responses[argv[1]] + "\n"
            if argv[0] == "diff":
                return responses["DIFF_ADDED"] if "--diff-filter=A" in argv else responses["DIFF_CHANGED"]
            raise AssertionError("unexpected git args " + repr(argv))
        env = {"GITHUB_EVENT_NAME": "pull_request", "GITHUB_RUN_ATTEMPT": "1",
               "GITHUB_REPOSITORY": "Public/fixture", "GITHUB_SHA": MERGE}
        with patch.object(pr, "ROOT", root), patch.object(pr, "git", side_effect=git), \
             patch.object(pr.typed, "ROOT", root), \
             patch.object(pr.typed, "REQUEST_DIR", root / "requests" / "gha"):
            yield root, env, event()


class PublicPRBoundary(unittest.TestCase):
    def test_positive_exactly_one_new_manifest(self):
        with candidate() as (_, env, ev):
            plan = pr.admit(environment=env, event=ev)
            self.assertEqual(plan["request_path"], FILE)
            self.assertEqual(plan["pr_head_sha"], HEAD)
            self.assertEqual(plan["source_sha"], MERGE)
            self.assertEqual(plan["runner"], "ubuntu-24.04")
            self.assertEqual(plan["workload"], "arithmetic-oracle")
            self.assertEqual(len(plan["request_sha256"]), 64)

    def test_unrelated_pr_is_noop(self):
        with candidate(changed=("tests/example.txt",), added=("tests/example.txt",)) as (_, env, ev):
            self.assertIsNone(pr.admit(environment=env, event=ev))

    def test_mixed_source_and_manifest_denied(self):
        with candidate(changed=(FILE, "scripts/malicious.py"),
                       added=(FILE, "scripts/malicious.py")) as (_, env, ev):
            with self.assertRaisesRegex(pr.Denied, "PR_NOT_EXACTLY_ONE_NEW_REQUEST"):
                pr.admit(environment=env, event=ev)

    def test_modified_existing_manifest_denied(self):
        with candidate(added=()) as (_, env, ev):
            with self.assertRaisesRegex(pr.Denied, "PR_NOT_EXACTLY_ONE_NEW_REQUEST"):
                pr.admit(environment=env, event=ev)

    def test_invalid_request_basename_denied(self):
        bad = "requests/gha/pr-EVIL.json"
        with candidate(changed=(bad,), added=(bad,)) as (_, env, ev):
            with self.assertRaisesRegex(pr.Denied, "PR_NOT_EXACTLY_ONE_NEW_REQUEST"):
                pr.admit(environment=env, event=ev)

    def test_filename_identity_mismatch_denied(self):
        payload = dict(manifest(), assignment_id="different-assignment")
        with candidate(payload=payload) as (_, env, ev):
            with self.assertRaisesRegex(pr.Denied, "PR_ASSIGNMENT_FILE_ID_MISMATCH"):
                pr.admit(environment=env, event=ev)

    def test_mismatched_merge_head_denied(self):
        with candidate(git_overrides={"HEAD^2": "f" * 40}) as (_, env, ev):
            with self.assertRaisesRegex(pr.Denied, "PR_MERGE_HEAD_DRIFT"):
                pr.admit(environment=env, event=ev)

    def test_outside_fork_denied(self):
        with candidate() as (_, env, ev):
            ev["pull_request"]["head"]["repo"]["full_name"] = "Other/repo"
            with self.assertRaisesRegex(pr.Denied, "PR_CROSS_REPOSITORY_DENIED"):
                pr.admit(environment=env, event=ev)

    def test_reopen_or_synchronize_denied(self):
        for action in ("synchronize", "reopened", "edited"):
            with self.subTest(action=action), candidate() as (_, env, ev):
                ev["action"] = action
                with self.assertRaisesRegex(pr.Denied, "PR_NOT_NEWLY_OPENED"):
                    pr.admit(environment=env, event=ev)

    def test_attempt_two_or_wrong_event_denied(self):
        for change in ({"GITHUB_RUN_ATTEMPT": "2"}, {"GITHUB_EVENT_NAME": "workflow_dispatch"}):
            with self.subTest(change=change), candidate() as (_, env, ev):
                env.update(change)
                with self.assertRaisesRegex(pr.Denied, "PR_EVENT_OR_REPLAY_DENIED"):
                    pr.admit(environment=env, event=ev)

    def test_duplicate_json_keys_denied_before_native_parser(self):
        with candidate() as (root, env, ev):
            file = root / FILE
            file.write_text(json.dumps(manifest()).replace(
                '"max_attempts": 1', '"max_attempts": 1, "max_attempts": 1'))
            with self.assertRaisesRegex(pr.Denied, "DUPLICATE_JSON_FIELD"):
                pr.admit(environment=env, event=ev)

    def test_bounded_static_profile_only(self):
        mutations = (("runner", "windows-2025"), ("workload", "run-shell"),
                     ("timeout_seconds", 200), ("max_cost_usd", 1),
                     ("data_class", "private"), ("max_attempts", 2))
        for field, value in mutations:
            with self.subTest(field=field), candidate(payload=dict(manifest(), **{field: value})) as (_, env, ev):
                with self.assertRaises((pr.Denied, pr.typed.Denied)):
                    pr.admit(environment=env, event=ev)

    def test_public_fixture_contains_no_untrusted_execution_primitives(self):
        source = (ROOT / "scripts" / "gha_pr_request.py").read_text()
        self.assertNotIn("pull_request_target", source)
        self.assertNotIn("shell=True", source)
        self.assertNotIn("eval(", source)


if __name__ == "__main__":
    unittest.main()
