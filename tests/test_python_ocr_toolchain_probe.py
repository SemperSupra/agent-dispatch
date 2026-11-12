"""Offline negative gates for a public-only, synthetic OCR toolchain probe."""
import hashlib
import importlib.util
import json
from pathlib import Path
import re
import tempfile
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
SOURCE = ROOT / "scripts" / "python_ocr_toolchain_probe.py"
spec = importlib.util.spec_from_file_location("public_ocr_candidate", SOURCE)
m = importlib.util.module_from_spec(spec)
spec.loader.exec_module(m)


class OCRCandidateContractTests(unittest.TestCase):
    def test_fixed_pdf_has_stable_hash_and_no_external_source(self):
        raw = m.fixed_pdf()
        self.assertEqual(hashlib.sha256(raw).hexdigest(), m.FIXTURE_HASH)
        self.assertTrue(raw.startswith(b"%PDF-1.4"))
        self.assertIn(b"(SYNTHETIC)", raw)
        self.assertEqual(raw.count(b"/Type /Page "), 1)

    def test_requested_base_is_immutable(self):
        self.assertEqual(m.BASE_REF, "python@sha256:9aaa474097d094040649f2162a627c0049b408f52138d980916788d80f04802f")
        image = (ROOT / "experiments/python-ocr-toolchain/Dockerfile").read_text()
        self.assertIn("ARG BASE=" + m.BASE_REF, image)
        self.assertNotIn("FROM python:", image)
        self.assertIn("USER 65532:65532", image)
        self.assertIn("COPY --chown=65532:65532 scripts/python_ocr_toolchain_probe.py", image)
        self.assertNotIn("COPY . .", image)

    def test_source_has_no_shell_or_patient_file_interface(self):
        source = SOURCE.read_text()
        self.assertNotIn("shell=True", source)
        self.assertNotIn("eval(", source)
        self.assertNotIn("exec(", source)
        self.assertNotIn("requests.get", source)
        self.assertNotIn("urllib.request", source)
        self.assertEqual(m.main([]), 2)

    def test_private_or_missing_runner_identity_is_refused_before_build(self):
        with tempfile.TemporaryDirectory() as temp:
            for env in ({}, {"GITHUB_REPOSITORY": "private/clinical", "RUNNER_ARCH": "X64"},
                        {"GITHUB_REPOSITORY": "SemperSupra/agent-dispatch", "RUNNER_ARCH": "unexpected"}):
                with self.subTest(env=env), mock.patch.dict(m.os.environ, env, clear=True):
                    with self.assertRaises(m.Denied):
                        m.outer_candidate(Path(temp) / "receipt.json")

    def test_unqualified_host_architecture_is_refused_before_build(self):
        with tempfile.TemporaryDirectory() as temp:
            with mock.patch.dict(m.os.environ, {"GITHUB_REPOSITORY": "SemperSupra/agent-dispatch", "RUNNER_ARCH": "X64"}), \
                 mock.patch.object(m.platform, "machine", return_value="aarch64"), \
                 mock.patch.object(m.shutil, "which", return_value="/usr/bin/docker"):
                with self.assertRaises(m.Denied):
                    m.outer_candidate(Path(temp) / "receipt.json")

    def test_wheel_inventory_hashes_only_six_bounded_real_files(self):
        capture = ROOT / "experiments/python-ocr-toolchain/wheel_capture.py"
        spec = importlib.util.spec_from_file_location("public_wheel_capture", capture)
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            for i in range(6):
                (root / f"candidate{i}-1.0-py3-none-any.whl").write_bytes(f"synthetic-wheel-{i}".encode())
            evidence = mod.index_wheels(root)
            self.assertEqual(len(evidence), 6)
            for item in evidence:
                self.assertEqual(item["sha256"],
                                 hashlib.sha256((root / item["filename"]).read_bytes()).hexdigest())
            (root / "candidate0-1.0-py3-none-any.whl").unlink()
            with self.assertRaises(ValueError):
                mod.index_wheels(root)
            target = root / "outside.data"
            target.write_bytes(b"synthetic")
            (root / "candidate0-1.0-py3-none-any.whl").symlink_to(target)
            with self.assertRaises(ValueError):
                mod.index_wheels(root)

    def test_build_nonzero_fails_without_receipt(self):
        with tempfile.TemporaryDirectory() as temp:
            output = Path(temp) / "receipt.json"
            failed = m.subprocess.CompletedProcess(["docker", "build"], 1, stdout="", stderr="synthetic build failed")
            with mock.patch.dict(m.os.environ, {"GITHUB_REPOSITORY": "SemperSupra/agent-dispatch", "RUNNER_ARCH": "X64"}), \
                 mock.patch.object(m.platform, "machine", return_value="x86_64"), \
                 mock.patch.object(m.shutil, "which", return_value="/usr/bin/docker"), \
                 mock.patch.object(m.os, "getuid", return_value=1000), \
                 mock.patch.object(m.subprocess, "run", return_value=failed) as command:
                with self.assertRaisesRegex(m.Denied, "build failed"):
                    m.outer_candidate(output)
            self.assertFalse(output.exists())
            self.assertEqual(command.call_count, 1)


if __name__ == "__main__":
    unittest.main()
