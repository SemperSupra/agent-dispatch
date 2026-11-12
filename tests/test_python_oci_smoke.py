"""No-network contract tests for the public, synthetic-only OCI smoke workcell."""
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("python_oci_smoke", ROOT / "scripts/python_oci_smoke.py")
m = importlib.util.module_from_spec(spec)
spec.loader.exec_module(m)


class PublicPythonOCIProbeTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name) / "external"
        (self.root / "outputs").mkdir(parents=True, mode=0o700)
        self.root.chmod(0o700)
        (self.root / "outputs").chmod(0o700)
        self.scratch = Path(self.tmp.name) / "scratch"
        self.scratch.mkdir(mode=0o700)
        (self.root / "input.bin").write_bytes(m.FIXTURE)

    def test_prepare_does_not_publish(self):
        self.assertEqual(m.child(self.root, self.scratch, "prepare"), "PREPARED")
        self.assertTrue((self.scratch / "plan.json").is_file())
        self.assertEqual(list((self.root / "outputs").iterdir()), [])

    def test_destroy_scratch_then_publish_and_replay(self):
        m.child(self.root, self.scratch, "prepare")
        import shutil
        shutil.rmtree(self.scratch)
        self.scratch.mkdir(mode=0o700)
        self.assertEqual(m.child(self.root, self.scratch, "publish"), "PUBLISHED")
        target = self.root / "outputs" / "result.json"
        initial = (target.read_bytes(), target.stat().st_ino)
        self.assertEqual(m.child(self.root, self.scratch, "publish"), "REUSED")
        self.assertEqual((target.read_bytes(), target.stat().st_ino), initial)
        self.assertEqual(target.stat().st_mode & 0o777, 0o600)

    def test_conflicting_result_is_never_replaced(self):
        m.child(self.root, self.scratch, "publish")
        target = self.root / "outputs" / "result.json"
        target.write_bytes(b"external actor modified result")
        with self.assertRaisesRegex(m.Rejected, "conflicting"):
            m.child(self.root, self.scratch, "publish")
        self.assertEqual(target.read_bytes(), b"external actor modified result")

    def test_invalid_source_fails_before_output(self):
        (self.root / "input.bin").write_bytes(b"NOT THE FIXED SYNTHETIC FIXTURE")
        with self.assertRaises(m.Rejected):
            m.child(self.root, self.scratch, "publish")
        self.assertFalse(list((self.root / "outputs").iterdir()))

    def test_symlinked_source_is_not_admitted(self):
        (self.root / "input.bin").unlink()
        other = Path(self.tmp.name) / "outside.bin"
        other.write_bytes(m.FIXTURE)
        (self.root / "input.bin").symlink_to(other)
        with self.assertRaises(m.Rejected):
            m.child(self.root, self.scratch, "publish")

    def test_symlinked_output_does_not_change_target(self):
        other = Path(self.tmp.name) / "outside.txt"
        other.write_bytes(b"preserve")
        (self.root / "outputs" / "result.json").symlink_to(other)
        with self.assertRaises(m.Rejected):
            m.child(self.root, self.scratch, "publish")
        self.assertEqual(other.read_bytes(), b"preserve")

    def test_nonprivate_or_overlapping_dirs_refused(self):
        self.root.chmod(0o755)
        with self.assertRaises(m.Rejected):
            m.child(self.root, self.scratch, "publish")
        self.root.chmod(0o700)
        with self.assertRaisesRegex(m.Rejected, "overlaps"):
            m.child(self.root, self.root, "publish")

    def test_result_contains_no_source_values_or_paths(self):
        m.child(self.root, self.scratch, "publish")
        blob = (self.root / "outputs" / "result.json").read_text()
        self.assertNotIn("PUBLIC-SYNTHETIC-FIXTURE", blob)
        self.assertNotIn(str(self.root), blob)
        self.assertEqual(json.loads(blob)["schema"], m.RECEIPT_SCHEMA)

    def test_public_job_identity_fail_closed(self):
        with mock.patch.dict(m.os.environ, {"GITHUB_REPOSITORY": "other/private"}):
            with self.assertRaises(m.Rejected):
                m.run_public_qualification(Path(self.tmp.name) / "receipt.json")

    def test_mutable_or_mismatched_image_identity_denied_before_execution(self):
        expected = m.IMAGE_CANDIDATE
        self.assertRegex(expected, r"^python@sha256:[a-f0-9]{64}$")
        pull_ok = m.subprocess.CompletedProcess(["docker", "pull"], 0, stdout="", stderr="")
        wrong = m.subprocess.CompletedProcess(["docker", "inspect"], 0,
                                              stdout="python@sha256:" + "0" * 64 + "\n", stderr="")
        with mock.patch.dict(m.os.environ, {"GITHUB_REPOSITORY": "SemperSupra/agent-dispatch",
                                            "RUNNER_ARCH": "X64"}), \
             mock.patch.object(m.platform, "machine", return_value="x86_64"), \
             mock.patch.object(m.shutil, "which", return_value="/usr/bin/docker"), \
             mock.patch.object(m.os, "getuid", return_value=1000), \
             mock.patch.object(m, "_subprocess", side_effect=[pull_ok, wrong]) as calls:
            with self.assertRaisesRegex(m.Rejected, "identity mismatch"):
                m.run_public_qualification(Path(self.tmp.name) / "receipt.json")
            self.assertEqual(calls.call_count, 2)
            self.assertEqual(calls.call_args_list[0].args[0][3], expected)

    def test_fixed_image_and_no_dynamic_shell(self):
        self.assertEqual(m.IMAGE_CANDIDATE, "python@sha256:9aaa474097d094040649f2162a627c0049b408f52138d980916788d80f04802f")
        source = (ROOT / "scripts/python_oci_smoke.py").read_text()
        self.assertNotIn("shell=True", source)
        self.assertNotIn("eval(", source)
        self.assertNotIn("exec(", source)


if __name__ == "__main__":
    unittest.main()
