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

    def test_wheel_and_ocr_packages_are_exactly_pinned(self):
        docker = (ROOT / "experiments/python-ocr-toolchain/Dockerfile").read_text()
        locked = (ROOT / "experiments/python-ocr-toolchain/requirements-candidate.txt").read_text()
        self.assertIn("--require-hashes", docker)
        self.assertEqual(docker.count("--require-hashes"), 2)
        for dep in ("attrs==26.1.0", "jsonschema==4.26.0",
                    "jsonschema-specifications==2025.9.1",
                    "pypdf==7.0.1", "referencing==0.37.0", "rpds-py==2026.9.1"):
            self.assertIn(dep, locked)
        self.assertEqual(locked.count("--hash=sha256:"), 7)
        for sha in ("07deecbfce94c78473018bc7d10b337cc651d12df87a1eb2cb3e4024bc9c33d0",
                    "eac2f5dbafd585dfe31f86a23ebf0d3ba480a9d49ebc87947267b5608d4ea0cd"):
            self.assertIn(sha, locked)
        for pin in ("ghostscript=10.05.1~dfsg-1+deb13u3",
                    "poppler-utils=25.03.0-5+deb13u4",
                    "tesseract-ocr=5.5.0-1+b1",
                    "tesseract-ocr-eng=1:4.1.0-2"):
            self.assertIn(pin, docker)

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
