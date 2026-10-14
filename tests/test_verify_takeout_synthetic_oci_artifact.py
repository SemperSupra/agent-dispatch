"""Offline synthetic OCI integrity negative tests; no Docker, network or secrets."""
import hashlib
import importlib.util
import io
import json
from pathlib import Path
import tarfile
import tempfile
import unittest
import zipfile

MODULE_PATH = Path(__file__).resolve().parents[1] / "scripts/verify_takeout_synthetic_oci_artifact.py"
spec = importlib.util.spec_from_file_location("synthetic_oci", MODULE_PATH)
v = importlib.util.module_from_spec(spec)
spec.loader.exec_module(v)

SOURCE = "5" * 40


def blob(data):
    return "sha256:" + hashlib.sha256(data).hexdigest()


def j(value):
    return json.dumps(value, sort_keys=True).encode("utf8")


def make_artifact(path, *, corrupt_layer=False, user="10001:10001",
                  claim="NOT_RUN", wrong_receipt=False):
    layers = [bytes([n]) * (n + 3) for n in range(5)]
    config = j({"os": "linux", "architecture": "amd64",
                "config": {"User": user, "Entrypoint": ["python3", "/app/fixture.py"],
                           "ExposedPorts": None}})
    manifest = j({"schemaVersion": 2,
                  "config": {"digest": blob(config), "size": len(config)},
                  "layers": [{"digest": blob(data), "size": len(data)} for data in layers]})
    index = j({"manifests": [{"digest": blob(manifest), "size": len(manifest),
                              "platform": {"os": "linux", "architecture": "amd64"}}]})
    contents = {"index.json": index, "oci-layout": j({"imageLayoutVersion": "1.0.0"}),
                "blobs/sha256/" + blob(manifest)[7:]: manifest,
                "blobs/sha256/" + blob(config)[7:]: config}
    for data in layers:
        contents["blobs/sha256/" + blob(data)[7:]] = data
    if corrupt_layer:
        name = "blobs/sha256/" + blob(layers[2])[7:]
        contents[name] = contents[name][:-1] + b"X"
    tar_buffer = io.BytesIO()
    with tarfile.open(fileobj=tar_buffer, mode="w") as archive:
        for name, data in contents.items():
            member = tarfile.TarInfo(name)
            member.size = len(data)
            archive.addfile(member, io.BytesIO(data))
    receipt = {"source_sha": SOURCE if not wrong_receipt else "1" * 40,
               "image_digest": blob(manifest), "guest": claim, "admission": "HOLD",
               "guest_attempt_budget": 0}
    with zipfile.ZipFile(path, "w", compression=zipfile.ZIP_DEFLATED) as zip_out:
        files = {"fixture.oci.tar": tar_buffer.getvalue(), "image.json": b"{}",
                 "loaded-config-digest.txt": blob(config).encode("ascii"),
                 "source-sha.txt": SOURCE.encode("ascii"), "receipt.json": j(receipt),
                 "first.json": b"{}", "restart.json": b"{}"}
        for name, data in files.items():
            zip_out.writestr(name, data)
    return blob(manifest)


class VerifyTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.path = Path(self.temp.name) / "artifact.zip"

    def check(self, *, corrupt_layer=False, user="10001:10001",
              claim="NOT_RUN", wrong_receipt=False):
        image = make_artifact(self.path, corrupt_layer=corrupt_layer,
                              user=user, claim=claim, wrong_receipt=wrong_receipt)
        return v.verify(self.path, v.file_hash(self.path), image, SOURCE)

    def test_correct_package(self):
        result = self.check()
        self.assertEqual((result["status"], result["layers"], result["uid"]),
                         ("PASS", 5, "10001:10001"))
        self.assertEqual(result["truenas_guest"], "NOT_RUN")

    def test_tampered_layer_even_with_rehashed_outer_zip(self):
        with self.assertRaisesRegex(v.Blocked, "TAMPERED_OCI_BLOB"):
            self.check(corrupt_layer=True)

    def test_forged_receipt_rejected(self):
        with self.assertRaisesRegex(v.Blocked, "RECEIPT_IDENTITY_MISMATCH"):
            self.check(wrong_receipt=True)

    def test_guest_success_claim_cannot_be_accepted(self):
        with self.assertRaisesRegex(v.Blocked, "INVALID_QUALIFICATION_CLAIM"):
            self.check(claim="PASS")

    def test_wrong_runtime_user(self):
        with self.assertRaisesRegex(v.Blocked, "WRONG_RUNTIME_USER"):
            self.check(user="0:0")

    def test_bad_outer_digest(self):
        image = make_artifact(self.path)
        with self.assertRaisesRegex(v.Blocked, "ARTIFACT_DIGEST_MISMATCH"):
            v.verify(self.path, "sha256:" + "0" * 64, image, SOURCE)

    def test_wrong_image_identity(self):
        make_artifact(self.path)
        with self.assertRaisesRegex(v.Blocked, "RECEIPT_IDENTITY_MISMATCH"):
            v.verify(self.path, v.file_hash(self.path), "sha256:" + "0" * 64, SOURCE)


if __name__ == "__main__":
    unittest.main()
