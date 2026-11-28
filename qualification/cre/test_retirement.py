"""Actual subprocess counterexamples for the bounded Docker retirement helper.

The Docker CLI is a controlled local fixture; this is NOT a live Docker, VM,
process-tree, resource teardown or production-provider qualification.
"""
from __future__ import annotations

import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

from qualification.cre.retirement import retire_owned_container

CID = "a" * 64
FOREIGN_ID = "b" * 64
NAME = "cre-public-0123456789abcdef0123456789abcdef"

FAKE_DOCKER = r'''
import json, os, sys, time
from pathlib import Path
root=Path(os.environ["FIXTURE_ROOT"])
p=root/"state.json"
s=json.loads(p.read_text())
mode=s["mode"]
args=sys.argv[1:]
s["commands"].append(args)
p.write_text(json.dumps(s))
if args[:1]==["inspect"]:
    print("SECRET-provider-error",file=sys.stderr)
    raise SystemExit(1)
if args[:4]==["container","ls","--all","--no-trunc"] and len(args)==6 and args[4]=="--format":
    s["observations"]+=1
    p.write_text(json.dumps(s))
    post=s["observations"]>1
    if mode in ("daemon_down","permission_denied") or (post and mode=="post_daemon_down"):
        print("SECRET-provider-error",file=sys.stderr)
        raise SystemExit(1)
    if post and mode=="post_malformed":
        print('{"ID":')
        raise SystemExit(0)
    if mode=="truncated_inventory":
        print(json.dumps(dict(ID="a"*12,Names=s["name"])))
        raise SystemExit(0)
    if mode=="duplicate_id":
        row=dict(ID=s["id"],Names=s["name"])
        print(json.dumps(row))
        print(json.dumps(dict(ID=s["id"],Names="other")))
        raise SystemExit(0)
    if mode=="duplicate_name":
        print(json.dumps(dict(ID=s["id"],Names=s["name"])))
        print(json.dumps(dict(ID="b"*64,Names=s["name"])))
        raise SystemExit(0)
    if mode=="partial_framing":
        sys.stdout.write(json.dumps(dict(ID=s["id"],Names=s["name"])))
        raise SystemExit(0)
    if mode=="duplicate_key":
        print('{"ID":"'+s["id"]+'","ID":"'+"b"*64+'","Names":"'+s["name"]+'"}')
        raise SystemExit(0)
    if mode=="name_reuse" or (post and mode=="replacement_after_remove"):
        print(json.dumps(dict(ID="b"*64,Names=s["name"])))
    elif mode=="id_name_changed":
        print(json.dumps(dict(ID=s["id"],Names="foreign-name")))
    elif mode!="absent" and not s["removed"]:
        print(json.dumps(dict(ID=s["id"],Names=s["name"])))
    raise SystemExit(0)
if args==["container","rm","--force",s["id"]] or args==["rm","-f",s["id"]]:
    if mode=="rm_timeout":
        time.sleep(2)
    if mode in ("daemon_down","permission_denied"):
        print("SECRET-provider-error",file=sys.stderr)
        raise SystemExit(1)
    if mode!="rm_false_success":
        s["removed"]=True
        p.write_text(json.dumps(s))
    if mode=="rm_failure_absent_after":
        print("SECRET-provider-error",file=sys.stderr)
        raise SystemExit(1)
    print("b"*64 if mode=="wrong_removal_identity" else s["id"])
    raise SystemExit(0)
print("unexpected command",file=sys.stderr)
raise SystemExit(2)
'''


class CLIFixture:
    def __init__(self, root, mode):
        import os
        self.root = root
        self.env = {**os.environ, "FIXTURE_ROOT": str(root)}
        self.script = root / "docker_fixture.py"
        self.script.write_text(FAKE_DOCKER)
        (root / "state.json").write_text(json.dumps({
            "mode": mode, "id": CID, "name": NAME, "removed": False,
            "observations": 0, "commands": [],
        }))

    def run(self, argv, timeout):
        if argv[0] != "docker":
            raise AssertionError("only Docker is admitted to this fixture")
        return subprocess.run(
            [sys.executable, str(self.script), *argv[1:]], env=self.env,
            capture_output=True, timeout=timeout, check=False,
        )

    def state(self):
        return json.loads((self.root / "state.json").read_text())


class RetirementTests(unittest.TestCase):
    def scenario(self, mode, owned_id=CID, timeout=1):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        fixture = CLIFixture(Path(tmp.name), mode)
        receipt = retire_owned_container(
            owned_id, NAME, run=fixture.run, timeout=timeout
        )
        self.assertNotIn("SECRET", json.dumps(receipt))
        return receipt, fixture.state()

    def test_baseline_nonzero_inspect_falsely_passes_real_error_processes(self):
        for mode in ("daemon_down", "permission_denied"):
            with self.subTest(mode=mode), tempfile.TemporaryDirectory() as d:
                fixture = CLIFixture(Path(d), mode)
                fixture.run(["docker", "rm", "-f", CID], 1)
                # Exact old acceptance predicate after an unchecked removal.
                legacy_cleanup = fixture.run(["docker", "inspect", CID], 1).returncode != 0
                self.assertTrue(legacy_cleanup)
                fixed = retire_owned_container(CID, NAME, run=fixture.run, timeout=1)
                self.assertEqual(fixed["status"], "UNKNOWN")

    def test_successful_exact_removal_and_complete_absence(self):
        r, s = self.scenario("removed")
        self.assertEqual((r["status"], r["reason"]), ("CONFIRMED_ABSENT", "removed_and_absent"))
        self.assertEqual(r["removal"]["status"], "SUCCEEDED")
        self.assertFalse(r["observations"]["after"]["owned_id_present"])
        removals = [c for c in s["commands"] if c[:2] == ["container", "rm"]]
        self.assertEqual(removals, [["container", "rm", "--force", CID]])

    def test_already_absent_is_idempotent_without_remove(self):
        r, s = self.scenario("absent")
        self.assertEqual((r["status"], r["reason"]), ("CONFIRMED_ABSENT", "already_absent"))
        self.assertEqual(len(s["commands"]), 1)
        self.assertEqual(r["removal"]["status"], "NOT_ATTEMPTED")

    def test_provider_or_permission_failure_is_unknown_without_mutation(self):
        for mode in ("daemon_down", "permission_denied"):
            with self.subTest(mode=mode):
                r, s = self.scenario(mode)
                self.assertEqual(r["status"], "UNKNOWN")
                self.assertEqual(r["reason"], "initial_observation_unknown")
                self.assertEqual(len(s["commands"]), 1)

    def test_removal_timeout_returns_unknown_receipt(self):
        r, s = self.scenario("rm_timeout", timeout=0.3)
        self.assertEqual(r["status"], "UNKNOWN")
        self.assertEqual(r["removal"]["status"], "TIMED_OUT")
        self.assertTrue(r["observations"]["after"]["owned_id_present"])
        self.assertEqual(s["observations"], 2)

    def test_failed_removal_is_unknown_even_after_empty_inventory(self):
        r, _ = self.scenario("rm_failure_absent_after")
        self.assertEqual(r["status"], "UNKNOWN")
        self.assertEqual(r["removal"]["status"], "FAILED")
        self.assertFalse(r["observations"]["after"]["owned_id_present"])

    def test_false_success_cannot_hide_remaining_container(self):
        r, _ = self.scenario("rm_false_success")
        self.assertEqual((r["status"], r["reason"]), ("PRESENT", "owned_container_remains"))

    def test_final_observation_failure_is_unknown(self):
        for mode in ("post_daemon_down", "post_malformed"):
            with self.subTest(mode=mode):
                r, _ = self.scenario(mode)
                self.assertEqual(r["status"], "UNKNOWN")
                self.assertEqual(r["reason"], "final_observation_unknown")

    def test_changed_binding_and_name_reuse_never_delete_foreign_body(self):
        for mode in ("name_reuse", "id_name_changed"):
            with self.subTest(mode=mode):
                r, s = self.scenario(mode)
                self.assertEqual(r["status"], "UNKNOWN")
                self.assertEqual(r["removal"]["status"], "NOT_ATTEMPTED")
                self.assertFalse(any("rm" in c for c in s["commands"]))

    def test_replacement_name_after_removal_is_not_absence(self):
        r, _ = self.scenario("replacement_after_remove")
        self.assertEqual((r["status"], r["reason"]), ("UNKNOWN", "name_reused"))

    def test_missing_launch_identity_never_settles_unknown_create(self):
        for mode in ("absent", "name_reuse"):
            with self.subTest(mode=mode):
                r, s = self.scenario(mode, owned_id=None)
                self.assertEqual((r["status"], r["reason"]), ("UNKNOWN", "launch_identity_unknown"))
                self.assertFalse(any("rm" in c for c in s["commands"]))

    def test_incomplete_or_ambiguous_inventory_is_unknown(self):
        for mode in ("truncated_inventory", "duplicate_id", "duplicate_name",
                     "partial_framing", "duplicate_key"):
            with self.subTest(mode=mode):
                r, s = self.scenario(mode)
                self.assertEqual(r["status"], "UNKNOWN")
                self.assertEqual(r["removal"]["status"], "NOT_ATTEMPTED")
                self.assertFalse(any("rm" in c for c in s["commands"]))

    def test_wrong_removal_identity_is_unknown(self):
        r, _ = self.scenario("wrong_removal_identity")
        self.assertEqual(r["status"], "UNKNOWN")
        self.assertEqual(r["removal"]["status"], "IDENTITY_UNCONFIRMED")

    def test_invalid_binding_never_calls_provider(self):
        def no_call(*_):
            raise AssertionError("provider must not run")
        for identifier, name in (("a" * 12, NAME), (CID, "--all"), (False, NAME),
                                 (CID, "bad name"), (CID, ""), (CID, "/alias")):
            with self.subTest(identifier=identifier, name=name):
                r = retire_owned_container(identifier, name, run=no_call)
                self.assertEqual((r["status"], r["reason"]), ("UNKNOWN", "invalid_binding"))

    def test_missing_executable_and_inventory_timeout_are_unknown(self):
        for failure in (FileNotFoundError(), PermissionError(),
                        subprocess.TimeoutExpired(["docker"], 1)):
            with self.subTest(failure=type(failure).__name__):
                def fail(*_):
                    raise failure
                r = retire_owned_container(CID, NAME, run=fail)
                self.assertEqual(r["status"], "UNKNOWN")
                self.assertEqual(r["removal"]["status"], "NOT_ATTEMPTED")

    def test_malformed_result_and_output_bound_are_unknown(self):
        results = [
            object(),
            subprocess.CompletedProcess([], True, b""),
            subprocess.CompletedProcess([], 0, "not bytes"),
            subprocess.CompletedProcess([], 0, b"x" * (1024 * 1024 + 1)),
            subprocess.CompletedProcess([], 0, b"\xff\n"),
            subprocess.CompletedProcess([], 0, b"[" * 1500 + b"]" * 1500 + b"\n"),
        ]
        for result in results:
            with self.subTest(result=type(result).__name__):
                r = retire_owned_container(CID, NAME, run=lambda *_: result)
                self.assertEqual(r["status"], "UNKNOWN")


if __name__ == "__main__":
    unittest.main(verbosity=2)
