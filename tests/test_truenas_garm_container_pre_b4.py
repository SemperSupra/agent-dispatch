import json
import pathlib
import sys
import tempfile
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

import truenas_middleware_garm_container_pre_b4_probe as probe


class ContainerPreB4Tests(unittest.TestCase):
    def fixture(self, producer="a" * 40):
        return {
            "schema": probe.EXPECTED_SCHEMA,
            "producer_source": producer,
            "target": {
                "system_version": probe.EXPECTED_VERSION,
                "driver": "container-v1",
                "control_surface": "container.*",
                "status": "OPEN",
                "required_methods": ["system.version", "container.query"],
            },
            "profile": "truenas-container-linux-general",
            "image_family": "ubuntu:noble:amd64:default",
            "expected_name": "garm-test",
            "source_oracles": {
                "runtime_admission_claimed": False,
                "github_jit_boundary_claimed": False,
            },
        }

    def test_load_accepts_exact_non_admitted_fixture(self):
        with tempfile.TemporaryDirectory() as td:
            root = pathlib.Path(td)
            doc = self.fixture()
            (root / "garm-provider-container-pre-b4-fixture.json").write_text(
                json.dumps(doc), encoding="utf-8"
            )
            self.assertEqual(probe.load_fixture(root, "a" * 40)["profile"], "truenas-container-linux-general")

    def test_load_rejects_runtime_admission_claim(self):
        with tempfile.TemporaryDirectory() as td:
            root = pathlib.Path(td)
            doc = self.fixture()
            doc["source_oracles"]["runtime_admission_claimed"] = True
            (root / "garm-provider-container-pre-b4-fixture.json").write_text(
                json.dumps(doc), encoding="utf-8"
            )
            with self.assertRaises(probe.ProbeError):
                probe.load_fixture(root, "a" * 40)

    def test_load_rejects_producer_drift(self):
        with tempfile.TemporaryDirectory() as td:
            root = pathlib.Path(td)
            (root / "garm-provider-container-pre-b4-fixture.json").write_text(
                json.dumps(self.fixture()), encoding="utf-8"
            )
            with self.assertRaises(probe.ProbeError):
                probe.load_fixture(root, "b" * 40)


if __name__ == "__main__":
    unittest.main()
