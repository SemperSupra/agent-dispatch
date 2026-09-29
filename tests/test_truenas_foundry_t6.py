#!/usr/bin/env python3
import importlib.util
import json
import pathlib
import tempfile
import unittest


HERE = pathlib.Path(__file__).resolve().parent
SPEC = importlib.util.spec_from_file_location(
    "foundry_t6", HERE / "truenas_middleware_foundry_control_probe.py"
)
MOD = importlib.util.module_from_spec(SPEC)
assert SPEC.loader
SPEC.loader.exec_module(MOD)


class FoundryT6ArtifactTests(unittest.TestCase):
    def artifact_dir(self, *, image="example@sha256:" + "a" * 64, bind=False):
        td = tempfile.TemporaryDirectory()
        root = pathlib.Path(td.name)
        service = {"image": image, "privileged": False}
        if bind:
            service["volumes"] = [{"type": "bind", "source": "/host", "target": "/data"}]
        compose = {"services": {"probe": service}}
        compose_sha = MOD.canonical_sha256(compose)
        artifact = {
            "schema": "truenas-foundry-deployment-artifact/v1",
            "runtime_target": "truenas-scale-apps",
            "app_name": "rdte-t6-probe",
            "compose_sha256": compose_sha,
            "materialization_identity": "sha256:" + compose_sha,
            "required_methods": ["app.query", "app.config", "app.create", "app.update"],
            "create_payload": {
                "custom_app": True,
                "app_name": "rdte-t6-probe",
                "custom_compose_config": compose,
            },
            "update_payload": {"custom_compose_config": compose},
        }
        artifact["artifact_sha256"] = MOD.canonical_sha256(artifact)
        artifact_path = root / "probe.deployment.json"
        raw = (json.dumps(artifact, indent=2, sort_keys=True) + "\n").encode()
        artifact_path.write_bytes(raw)
        index = {
            "schema": "truenas-foundry-materialized-controls/v1",
            "upstream": {"ref": "b" * 40},
            "controls": [{
                "app": "probe",
                "runtime_safe": True,
                "qualification_role": MOD.CONTROL_ROLE,
                "deployment_artifact_path": artifact_path.name,
                "deployment_artifact_file_sha256": __import__("hashlib").sha256(raw).hexdigest(),
                "deployment_artifact_sha256": artifact["artifact_sha256"],
                "source_compose_sha256": "c" * 64,
                "image_digests": {"probe": image},
                "target_lowering": {"published_port": 32080},
            }],
        }
        (root / "index.json").write_text(json.dumps(index), encoding="utf-8")
        return td, root, artifact

    def test_accepts_exact_runtime_safe_digest_pinned_artifact(self):
        td, root, artifact = self.artifact_dir()
        try:
            _, control, got = MOD.validate_artifact(root)
            self.assertEqual(control["qualification_role"], MOD.CONTROL_ROLE)
            self.assertEqual(got["artifact_sha256"], artifact["artifact_sha256"])
        finally:
            td.cleanup()

    def test_rejects_mutable_image(self):
        td, root, _ = self.artifact_dir(image="example:latest")
        try:
            with self.assertRaises(RuntimeError):
                MOD.validate_artifact(root)
        finally:
            td.cleanup()

    def test_rejects_host_bind(self):
        td, root, _ = self.artifact_dir(bind=True)
        try:
            with self.assertRaises(RuntimeError):
                MOD.validate_artifact(root)
        finally:
            td.cleanup()


if __name__ == "__main__":
    unittest.main()
