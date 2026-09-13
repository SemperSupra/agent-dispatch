import base64
import hashlib
import io
import tarfile
import tempfile
import unittest
from pathlib import Path

import sys
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))

import sealed_public_execution as worker


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
        self.assertEqual(worker._validate_recipient("age1qqqqqqqq"), "age1qqqqqqqq")
        with self.assertRaises(worker.WorkerError):
            worker._validate_recipient("not-a-recipient")

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


if __name__ == "__main__":
    unittest.main()
