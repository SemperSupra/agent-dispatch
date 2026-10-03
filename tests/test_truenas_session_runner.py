#!/usr/bin/env python3
import json
import pathlib
import stat
import sys
import tempfile
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

import truenas_session_manifest as manifest_mod
import truenas_session_runner as runner
from truenas_session_manifest import SessionError

TARGETS = ROOT / "config" / "truenas-rdte-targets.json"
PROVIDERS = ROOT / "config" / "truenas-capsule-providers.json"


def capsule(cid, provider, port, dependencies=None):
    return {
        "schema": "truenas-capsule/v1",
        "id": cid,
        "kind": "official-catalog-control" if provider == "official-catalog-t6" else "foundry-product",
        "provider": provider,
        "authority": {"repository": "SemperSupra/truenas-app-foundry-private", "issue": 282},
        "exact": {"source_ref": "0123456789012345678901234567890123456789", "artifact": "fixture"},
        "namespace": f"rdte-{cid}",
        "ports": [port],
        "requirements": ["apps", "zfs-pool"],
        "resources": {"memory_mib": 1024, "download_mib": 128, "estimated_minutes": 5},
        "phases": {"setup": True, "apply": True, "verify": True, "cleanup": True},
        "oracle": "existing provider oracle",
        "receipt_contract": "truenas-capsule-execution/v1",
        "retry_policy": "read-only-reconcile",
        "mutating": True,
        "cleanup_required": True,
        "dependencies": dependencies or [],
    }


def manifest(capsules):
    doc = {
        "schema": "truenas-session/v1",
        "session_id": "tn-26-beta3-runner-static-001",
        "version": "26.0.0-BETA.3",
        "authority": {"repository": "SemperSupra/agent-dispatch-private", "issue": 480},
        "budget": {"guest_memory_mib": 8192, "download_mib": 1024, "timeout_minutes": 45},
        "pool": {"name": "rdtepool", "data_disks": 2},
        "capsules": capsules,
    }
    doc["manifest_sha256"] = manifest_mod.manifest_digest(doc)
    return doc


FAKE_EXECUTOR = r"""#!/usr/bin/env python3
import argparse, json, pathlib, sys
p=argparse.ArgumentParser()
p.add_argument("--capsule", required=True)
p.add_argument("--context", required=True)
p.add_argument("--out", required=True)
a=p.parse_args()
desc=json.loads(pathlib.Path(a.capsule).read_text())
ctx=json.loads(pathlib.Path(a.context).read_text())
cap=desc["capsule"]; provider=desc["provider"]
cfg=ctx[cap["id"]]
if cfg.get("emit") is False:
    raise SystemExit(cfg.get("returncode", 3))
receipt={
  "schema":"truenas-capsule-execution/v1",
  "capsule_id":cap["id"],
  "provider":cap["provider"],
  "provider_probe":provider["probe"],
  "manifest_sha256":desc["manifest_sha256"],
  "verdict":cfg.get("verdict","SUPPORTED"),
  "mutating":cap["mutating"],
  "cleanup_required":cap["cleanup_required"],
  "cleanup_satisfied":cfg.get("cleanup_satisfied",True),
  "platform_healthy":cfg.get("platform_healthy",True),
  "authority_satisfied":cfg.get("authority_satisfied",True),
  "resource_guardrail_satisfied":cfg.get("resource_guardrail_satisfied",True)
}
if "manifest_sha256" in cfg:
    receipt["manifest_sha256"]=cfg["manifest_sha256"]
pathlib.Path(a.out).write_text(json.dumps(receipt))
raise SystemExit(cfg.get("returncode",0))
"""


class SessionRunnerTests(unittest.TestCase):
    def temp_json(self, value):
        f = tempfile.NamedTemporaryFile("w", suffix=".json", delete=False)
        with f:
            json.dump(value, f, indent=2, sort_keys=True)
            f.write("\n")
        path = pathlib.Path(f.name)
        self.addCleanup(lambda: path.unlink(missing_ok=True))
        return path

    def executor(self):
        f = tempfile.NamedTemporaryFile("w", suffix=".py", delete=False)
        with f:
            f.write(FAKE_EXECUTOR)
        path = pathlib.Path(f.name)
        path.chmod(path.stat().st_mode | stat.S_IXUSR)
        self.addCleanup(lambda: path.unlink(missing_ok=True))
        return path

    def execute_session(self, doc, context):
        root = pathlib.Path(tempfile.mkdtemp())
        self.addCleanup(lambda: __import__("shutil").rmtree(root, ignore_errors=True))
        return runner.run_session(
            self.temp_json(doc),
            TARGETS,
            PROVIDERS,
            self.executor(),
            self.temp_json(context),
            root / "receipts",
        )

    def test_clean_session_preserves_independent_product_failure(self):
        doc = manifest([
            capsule("catalog-control", "official-catalog-t6", 18080),
            capsule("foliorelay", "foliorelay-t6", 18081),
        ])
        result = self.execute_session(doc, {
            "catalog-control": {"verdict": "SUPPORTED"},
            "foliorelay": {"verdict": "ORACLE_FAILURE"},
        })
        self.assertEqual(result["classification"], "SESSION_CLEAN")
        self.assertTrue(result["session_clean"])
        self.assertFalse(result["product_acceptance_inferred"])
        self.assertEqual([x["verdict"] for x in result["capsules"]], ["SUPPORTED", "ORACLE_FAILURE"])

    def test_cleanup_failure_stops_later_mutation(self):
        doc = manifest([
            capsule("first", "official-catalog-t6", 18080),
            capsule("second", "foliorelay-t6", 18081),
        ])
        result = self.execute_session(doc, {
            "first": {"verdict": "ORACLE_FAILURE", "cleanup_satisfied": False},
            "second": {"verdict": "SUPPORTED"},
        })
        self.assertEqual(result["classification"], "SESSION_CONTAMINATED")
        self.assertEqual(result["capsules"][1]["verdict"], "NOT_EXECUTED")
        self.assertIn("SESSION_CONTAMINATED", result["capsules"][1]["reason"])

    def test_failed_dependency_skips_only_dependent_capsule(self):
        doc = manifest([
            capsule("first", "official-catalog-t6", 18080),
            capsule("dependent", "foliorelay-t6", 18081, ["first"]),
            capsule("independent", "garm-t6", 18082),
        ])
        result = self.execute_session(doc, {
            "first": {"verdict": "ORACLE_FAILURE"},
            "dependent": {"verdict": "SUPPORTED"},
            "independent": {"verdict": "SUPPORTED"},
        })
        verdicts = {x["capsule_id"]: x["verdict"] for x in result["capsules"]}
        self.assertEqual(verdicts["first"], "ORACLE_FAILURE")
        self.assertEqual(verdicts["dependent"], "NOT_EXECUTED")
        self.assertEqual(verdicts["independent"], "SUPPORTED")
        self.assertEqual(result["classification"], "SESSION_CLEAN")

    def test_executor_without_receipt_fails_closed(self):
        doc = manifest([
            capsule("first", "official-catalog-t6", 18080),
            capsule("second", "foliorelay-t6", 18081),
        ])
        result = self.execute_session(doc, {
            "first": {"emit": False, "returncode": 7},
            "second": {"verdict": "SUPPORTED"},
        })
        self.assertEqual(result["classification"], "SESSION_CONTAMINATED")
        self.assertEqual(result["capsules"][0]["verdict"], "HARNESS_FAILURE")
        self.assertFalse(result["capsules"][0]["platform_healthy"])
        self.assertEqual(result["capsules"][1]["verdict"], "NOT_EXECUTED")

    def test_receipt_manifest_drift_fails_closed(self):
        doc = manifest([capsule("first", "official-catalog-t6", 18080)])
        with self.assertRaisesRegex(SessionError, "receipt manifest identity mismatch"):
            self.execute_session(doc, {
                "first": {
                    "verdict": "SUPPORTED",
                    "manifest_sha256": "0" * 64,
                }
            })


if __name__ == "__main__":
    unittest.main()
