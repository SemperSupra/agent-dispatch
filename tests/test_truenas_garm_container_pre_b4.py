import json
import pathlib
import sys
import tempfile
import unittest
from unittest import mock

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
            f"/mnt/.truenas_containers/rdtepool/containers/{name}",
        )
        with self.assertRaises(probe.ProbeError):
            probe.derive_rootfs_mountpoint(
                doc, "rdtepool", name, f"rdtepool/foreign_layout/{name}"
            )

    def test_rootfs_projection_rejects_noncanonical_pool_and_name(self):
        doc = self.fixture()
        for pool, name in ((".", "garm-test"), ("..", "garm-test"),
                           ("rdtepool/..", "garm-test"), ("rdtepool", "../other"),
                           ("rdtepool", ".")):
            with self.subTest(pool=pool, name=name), self.assertRaises(probe.ProbeError):
                dataset = f"{pool}/.truenas_containers/containers/{name}"
                probe.derive_rootfs_mountpoint(doc, pool, name, dataset)

    def test_invalid_pool_stops_before_network_and_create(self):
        with tempfile.TemporaryDirectory() as td:
            out = pathlib.Path(td) / "receipt.json"
            args = ["probe", "--http-port", "80", "--middleware-port", "6000",
                    "--password-file", str(pathlib.Path(td) / "missing-password"),
                    "--fixture-dir", td, "--fixture-producer-commit", "a" * 40,
                    "--pool", "..", "--out", str(out)]
            with mock.patch.object(sys, "argv", args), \
                    mock.patch.object(probe, "load_fixture", return_value=self.fixture()), \
                    mock.patch.object(probe, "WebSocket", side_effect=AssertionError("network reached")):
                self.assertEqual(probe.main(), 2)
            self.assertFalse((pathlib.Path(td) / "missing-password").exists())
            self.assertFalse(json.loads(out.read_text())["cleanup"]["attempted"])

    def test_staged_traversal_rejected_before_any_upload(self):
        uploads = []
        fixture = {"staged_files": [{"path": "/usr/local/bin/bootstrap"},
                                    {"path": "/../../../../etc/forged"}]}
        with self.assertRaises(probe.ProbeError):
            probe.stage_bootstrap_files(
                fixture, "/mnt/.truenas_containers/rdtepool/containers/garm-test", "token",
                lambda *args: uploads.append(args), lambda *args: None, lambda *args: None,
            )
        self.assertEqual(uploads, [])

    def test_retirement_rechecks_created_identity_before_stop_and_delete(self):
        expected = {"id": 7, "uuid": "43e983d3-b812-456e-b39c-12ac68500b3f",
                    "name": "garm-test", "description": "owned",
                    "dataset": "rdtepool/.truenas_containers/containers/garm-test",
                    }
        for replace_at, want_stops, changed_field, replacement in (
            (1, 0, "description", "foreign"),
            (2, 1, "uuid", "2c85e1da-7a63-4579-8d57-96359ecf4ee0"),
        ):
            with self.subTest(replace_at=replace_at, field=changed_field):
                row = {**expected, "status": {"state": "RUNNING"}}
                calls = []
                reads = 0
                def call(method, params):
                    nonlocal row, reads
                    calls.append(method)
                    if method == "container.query":
                        reads += 1
                        if reads == replace_at:
                            row = {**row, changed_field: replacement}
                        query_field, _, value = params[0][0]
                        return [row] if row and row.get(query_field) == value else []
                    if method == "container.stop":
                        row = {**row, "status": {"state": "STOPPED"}}
                        return None
                    if method == "container.delete":
                        row = None
                        return None
                    raise AssertionError(method)
                with self.assertRaises(probe.ProbeError):
                    probe.retire_created_container(call, expected, {"force": True}, lambda *args: None, 0)
                self.assertEqual(calls.count("container.stop"), want_stops)
                self.assertNotIn("container.delete", calls)

    def test_retirement_requires_id_and_name_absence(self):
        expected = {"id": 7, "uuid": "43e983d3-b812-456e-b39c-12ac68500b3f",
                    "name": "garm-test", "description": "owned",
                    "dataset": "rdtepool/.truenas_containers/containers/garm-test",
                    }
        row = {**expected, "status": {"state": "STOPPED"}}
        def call(method, params):
            if method == "container.query":
                field, _, value = params[0][0]
                return [row] if row.get(field) == value else []
            if method == "container.delete":
                return None  # Acknowledged, but retained.
            raise AssertionError(method)
        with self.assertRaises(probe.ProbeError):
            probe.retire_created_container(call, expected, {}, lambda *args: None, 0)

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
