import json
import pathlib
import tempfile
import unittest

from scripts import truenas_middleware_garm_container_pre_b4_probe as probe


def fixture_doc():
    return {
        "schema": probe.EXPECTED_SCHEMA,
        "producer_source": "a" * 40,
        "target": {
            "system_version": probe.EXPECTED_VERSION,
            "middleware_commit": probe.EXPECTED_MIDDLEWARE,
            "driver": probe.EXPECTED_DRIVER,
            "control_surface": probe.EXPECTED_CONTROL,
            "status": "OPEN",
            "required_methods": [
                "system.version",
                "container.query",
                "container.create",
                "container.update",
                "container.start",
                "container.stop",
                "container.delete",
                "container.image.query_registry",
                "pool.dataset.query",
                "filesystem.put",
                "filesystem.stat",
            ],
        },
        "image_family": "ubuntu:noble:amd64:default",
        "desired_create": {
            "description": "{}",
            "autostart": False,
            "idmap_type": "DEFAULT",
            "capabilities_policy": "DEFAULT",
            "init": "/bin/sh /usr/local/bin/garm-container-init",
            "initenv": {
                "GARM_CALLBACK_URL": "http://synthetic/callback",
                "GARM_METADATA_URL": "http://synthetic/metadata",
                "RUNNER_ALLOW_RUNASROOT": "1",
            },
        },
        "staged_files": [
            {
                "path": "/usr/local/bin/garm-runner-bootstrap",
                "mode": 0o755,
                "content": "#!/bin/sh\nexit 1\n",
                "sha256": probe.canonical_sha256(b"#!/bin/sh\nexit 1\n"),
                "contains_secret": False,
            },
            {
                "path": "/usr/local/bin/garm-container-init",
                "mode": 0o755,
                "content": "#!/bin/sh\nexit 1\n",
                "sha256": probe.canonical_sha256(b"#!/bin/sh\nexit 1\n"),
                "contains_secret": False,
            },
            {
                "path": probe.TOKEN_PATH,
                "mode": 0o600,
                "content": probe.TOKEN_PLACEHOLDER,
                "sha256": probe.canonical_sha256(probe.TOKEN_PLACEHOLDER.encode()),
                "contains_secret": True,
            },
        ],
        "execution_markers": [probe.INIT_MARKER, probe.CHILD_MARKER],
        "expected_post_start": {"init": "/sbin/init", "initenv": {}},
        "source_oracles": {
            "supported_rootfs_staging_defined": True,
            "create_arguments_credential_free": True,
            "credential_pipe_staging_required": True,
            "credential_file_delete_required": True,
            "temporary_init_scrub_required": True,
            "runner_root_under_default_idmap_explicit": True,
            "external_restart_forbidden": True,
            "active_delete_refused": True,
            "final_absence_required": True,
            "per_runner_memory_isolation_claimed": False,
            "runtime_admission_claimed": False,
            "bootstrap_execution_claimed": False,
            "github_jit_boundary_claimed": False,
        },
        "expected_name": "garm-test-runner",
    }


class ContainerPreB4Tests(unittest.TestCase):
    def write_fixture(self, doc):
        td = tempfile.TemporaryDirectory()
        self.addCleanup(td.cleanup)
        root = pathlib.Path(td.name)
        (root / "garm-provider-container-pre-b4-fixture.json").write_text(
            json.dumps(doc) + "\n", encoding="utf-8"
        )
        return root

    def test_fixture_contract_accepts_only_open_nonadmitted_projection(self):
        doc = fixture_doc()
        root = self.write_fixture(doc)
        loaded = probe.load_fixture(root, "a" * 40)
        self.assertEqual(loaded["target"]["status"], "OPEN")
        self.assertNotIn("GARM_INSTANCE_TOKEN", loaded["desired_create"]["initenv"])
        self.assertFalse(loaded["source_oracles"]["runtime_admission_claimed"])
        self.assertFalse(loaded["source_oracles"]["github_jit_boundary_claimed"])

    def test_fixture_rejects_credential_in_create_arguments(self):
        doc = fixture_doc()
        doc["desired_create"]["initenv"]["GARM_INSTANCE_TOKEN"] = "forbidden"
        root = self.write_fixture(doc)
        with self.assertRaisesRegex(probe.ProbeError, "create arguments"):
            probe.load_fixture(root, "a" * 40)

    def test_fixture_rejects_backend_support_promotion(self):
        doc = fixture_doc()
        doc["target"]["status"] = "PASS"
        root = self.write_fixture(doc)
        with self.assertRaisesRegex(probe.ProbeError, "runtime admission"):
            probe.load_fixture(root, "a" * 40)

    def test_multipart_builder_keeps_file_bytes_exact(self):
        content = b"synthetic-bytes\x00\xff"
        body, boundary = probe.multipart_body(
            '{"method":"filesystem.put","params":["/mnt/test",{"mode":384}]}',
            "testfile",
            content,
        )
        self.assertIn(content, body)
        self.assertIn(boundary.encode(), body)
        self.assertIn(b'name="data"', body)
        self.assertIn(b'name="file"; filename="testfile"', body)

    def test_state_normalizes_string_and_nested_forms(self):
        self.assertEqual(probe.state(None), "ABSENT")
        self.assertEqual(probe.state({"status": "RUNNING"}), "RUNNING")
        self.assertEqual(probe.state({"status": {"state": "STOPPED"}}), "STOPPED")
        self.assertEqual(probe.state({"status": {"unexpected": True}}), "UNKNOWN")


if __name__ == "__main__":
    unittest.main()
