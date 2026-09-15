import base64
import hashlib
import io
import json
import tarfile
import tempfile
import unittest
from pathlib import Path

import sys
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))

import sealed_public_execution as worker


VALID_AGE_RECIPIENT = "age1" + "q" * 58


def make_capsule(entries):
    buffer = io.BytesIO()
    with tarfile.open(fileobj=buffer, mode="w:gz") as tf:
        for name, content, kind in entries:
            info = tarfile.TarInfo(name)
            if kind == "file":
                data = content.encode()
                info.size = len(data)
                info.mode = 0o644
                tf.addfile(info, io.BytesIO(data))
            elif kind == "symlink":
                info.type = tarfile.SYMTYPE
                info.linkname = content
                tf.addfile(info)
    return buffer.getvalue()


class SealedExecutionContractTests(unittest.TestCase):
    def test_assignment_ids_are_bounded(self):
        self.assertEqual(worker._validate_assignment_id("rep-001"), "rep-001")
        with self.assertRaises(worker.WorkerError):
            worker._validate_assignment_id("../escape")

    def test_age_recipient_shape_is_required(self):
        self.assertEqual(worker._validate_recipient(VALID_AGE_RECIPIENT), VALID_AGE_RECIPIENT)
        for invalid in ("not-a-recipient", "age1qqqqqqqq", "AGE1" + "q" * 58):
            with self.assertRaises(worker.WorkerError):
                worker._validate_recipient(invalid)

    def test_decode_requires_matching_digest(self):
        raw = make_capsule([("run.sh", "echo ok\n", "file")])
        encoded = base64.b64encode(raw).decode()
        with tempfile.TemporaryDirectory() as td:
            path = worker.decode_capsule(encoded, hashlib.sha256(raw).hexdigest(), Path(td))
            self.assertEqual(path.read_bytes(), raw)
            with self.assertRaises(worker.WorkerError):
                worker.decode_capsule(encoded, "0" * 64, Path(td))

    def test_safe_extract_accepts_top_level_runner(self):
        raw = make_capsule([
            ("run.sh", "mkdir -p \"$SEALED_RESULT_DIR\"; echo ok > \"$SEALED_RESULT_DIR/out.txt\"\n", "file"),
            ("probe.json", "{}\n", "file"),
        ])
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            capsule = root / "capsule.tar.gz"
            capsule.write_bytes(raw)
            worker.safe_extract(capsule, root / "work")
            self.assertTrue((root / "work" / "run.sh").is_file())

    def test_safe_extract_rejects_traversal(self):
        raw = make_capsule([
            ("run.sh", "echo ok\n", "file"),
            ("../escape", "bad\n", "file"),
        ])
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            capsule = root / "capsule.tar.gz"
            capsule.write_bytes(raw)
            with self.assertRaises(worker.WorkerError):
                worker.safe_extract(capsule, root / "work")

    def test_safe_extract_rejects_links(self):
        raw = make_capsule([
            ("run.sh", "echo ok\n", "file"),
            ("link", "../outside", "symlink"),
        ])
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            capsule = root / "capsule.tar.gz"
            capsule.write_bytes(raw)
            with self.assertRaises(worker.WorkerError):
                worker.safe_extract(capsule, root / "work")

    def test_result_budget_truncates_streams_without_failing_small_results(self):
        with tempfile.TemporaryDirectory() as td:
            result = Path(td) / "result"
            files = result / "files"
            files.mkdir(parents=True)
            (files / "out.json").write_text("{}\n", encoding="utf-8")
            large = b"A" * (worker.MAX_CAPTURED_STREAM_BYTES + 4096)
            (result / "stdout.txt").write_bytes(large)
            (result / "stderr.txt").write_bytes(b"small\n")

            budget = worker.enforce_result_budget(result)

            self.assertFalse(budget["exceeded"])
            self.assertTrue(budget["observed"]["stdout"]["truncated"])
            self.assertLessEqual(
                (result / "stdout.txt").stat().st_size,
                worker.MAX_CAPTURED_STREAM_BYTES,
            )
            self.assertTrue((files / "out.json").is_file())

    def test_result_budget_replaces_oversized_result_with_diagnostic(self):
        with tempfile.TemporaryDirectory() as td:
            result = Path(td) / "result"
            files = result / "files"
            files.mkdir(parents=True)
            (result / "stdout.txt").write_bytes(b"ok\n")
            (result / "stderr.txt").write_bytes(b"")
            (files / "too-large.bin").write_bytes(
                b"X" * (worker.MAX_RESULT_FILE_BYTES + 1)
            )

            budget = worker.enforce_result_budget(result)

            self.assertTrue(budget["exceeded"])
            self.assertFalse((files / "too-large.bin").exists())
            diagnostic = files / "result-budget-exceeded.json"
            self.assertTrue(diagnostic.is_file())
            stored = json.loads(diagnostic.read_text(encoding="utf-8"))
            self.assertTrue(stored["exceeded"])
            self.assertIn(
                "a result file exceeds the per-file byte limit",
                stored["violations"],
            )

    def test_result_budget_rejects_excessive_file_count(self):
        with tempfile.TemporaryDirectory() as td:
            result = Path(td) / "result"
            files = result / "files"
            files.mkdir(parents=True)
            (result / "stdout.txt").write_bytes(b"")
            (result / "stderr.txt").write_bytes(b"")
            for index in range(worker.MAX_RESULT_FILES + 1):
                (files / f"{index:04d}.txt").write_text("x", encoding="utf-8")

            budget = worker.enforce_result_budget(result)

            self.assertTrue(budget["exceeded"])
            self.assertEqual(len(list(files.iterdir())), 1)
            self.assertTrue((files / "result-budget-exceeded.json").is_file())


if __name__ == "__main__":
    unittest.main()
