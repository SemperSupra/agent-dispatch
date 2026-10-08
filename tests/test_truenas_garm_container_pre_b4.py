import json
import pathlib
import sys
import tempfile
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

import truenas_middleware_garm_container_pre_b4_probe as probe


class ContainerPreB4Tests(unittest.TestCase):
    def test_probe_and_harness_propagate_tls(self):
        script = (ROOT / "scripts" / "truenas_middleware_garm_container_pre_b4_probe.py").read_text(encoding="utf-8")
        harness = (ROOT / "scripts" / "gha_kvm_truenas_rdte.sh").read_text(encoding="utf-8")
        self.assertIn('p.add_argument("--tls", action="store_true")', script)
        self.assertIn("tls=a.tls", script)
        self.assertIn('"${MIDDLEWARE_TLS_ARG[@]}"', harness)

    def fixture(self, producer="a" * 40):
        return {
            "schema": probe.EXPECTED_SCHEMA,
            "producer_source": producer,
            "target": {
                "system_version": probe.EXPECTED_VERSION,
                "driver": "container-v1",
                "control_surface": "container.*",
                "status": "OPEN",
                "required_methods": ["system.version", "container.query", "filesystem.put", "filesystem.stat"],
            },
            "rootfs_projection": {
                "dataset_template": probe.EXPECTED_DATASET_TEMPLATE,
                "mountpoint_template": probe.EXPECTED_MOUNTPOINT_TEMPLATE,
                "source_path": probe.EXPECTED_ROOTFS_SOURCE,
            },
            "profile": "truenas-container-linux-general",
            "image_family": "ubuntu:noble:amd64:default",
            "expected_name": "garm-test",
            "source_oracles": {
                "runtime_admission_claimed": False,
                "github_jit_boundary_claimed": False,
                "source_derived_rootfs_projection_required": True,
            },
        }

    def test_rootfs_projection_is_exact_and_fail_closed(self):
        doc = self.fixture()
        name = doc["expected_name"]
        dataset = f"rdtepool/.truenas_containers/containers/{name}"
        self.assertEqual(
            probe.derive_rootfs_mountpoint(doc, "rdtepool", name, dataset),
            f"/.truenas_containers/rdtepool/containers/{name}",
        )
        with self.assertRaises(probe.ProbeError):
            probe.derive_rootfs_mountpoint(
                doc, "rdtepool", name, f"rdtepool/foreign_layout/{name}"
            )

    def test_load_rejects_hidden_dataset_query_reintroduction(self):
        with tempfile.TemporaryDirectory() as td:
            root = pathlib.Path(td)
            doc = self.fixture()
            doc["target"]["required_methods"].append("pool.dataset.query")
            (root / "garm-provider-container-pre-b4-fixture.json").write_text(
                json.dumps(doc), encoding="utf-8"
            )
            with self.assertRaises(probe.ProbeError):
                probe.load_fixture(root, "a" * 40)

    def test_not_found_classifier_is_fail_closed(self):
        self.assertTrue(probe.is_explicit_not_found(RuntimeError('filesystem.stat: {"error": 2, "reason": "Path not found"}')))
        self.assertTrue(probe.is_explicit_not_found(RuntimeError("ENOENT")))
        self.assertFalse(probe.is_explicit_not_found(RuntimeError("authentication failed")))
        self.assertFalse(probe.is_explicit_not_found(RuntimeError("transport timeout")))

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
