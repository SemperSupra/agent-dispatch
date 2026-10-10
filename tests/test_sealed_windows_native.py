#!/usr/bin/env python3
"""Native Windows sealed-public-execution synthetic roundtrip; no private source."""

from __future__ import annotations

import base64
import hashlib
import io
import json
import re
import shutil
import subprocess
import sys
import tarfile
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
import sealed_public_execution as worker


@unittest.skipUnless(sys.platform == "win32", "requires native Windows PowerShell 5.1")
class SealedWindowsNativeTests(unittest.TestCase):
    def test_real_ps51_and_age_sealing(self):
        for tool in ("powershell.exe", "age", "age-keygen"):
            self.assertIsNotNone(shutil.which(tool), f"missing native tool: {tool}")
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            identity = root / "identity.txt"
            keygen = subprocess.run(
                ["age-keygen", "-o", str(identity)],
                check=True, capture_output=True, text=True, timeout=30,
            )
            match = re.search(r"Public key:\s*(age1[0-9a-z]+)", keygen.stderr)
            self.assertIsNotNone(match, "age-keygen public recipient absent")
            recipient = match.group(1)

            script = (
                "$ErrorActionPreference = 'Stop'\n"
                "$target = Join-Path $env:SEALED_RESULT_DIR 'native.txt'\n"
                "'WINPS51_OK' | Set-Content -LiteralPath $target -Encoding ASCII\n"
                "exit 0\n"
            )
            archive = io.BytesIO()
            with tarfile.open(fileobj=archive, mode="w:gz") as tf:
                payload = script.encode("utf-8")
                entry = tarfile.TarInfo("run.ps1")
                entry.mode = 0o644
                entry.size = len(payload)
                tf.addfile(entry, io.BytesIO(payload))
                # A capsule-local executable must not replace the native interpreter.
                decoy = b"not-a-valid-windows-executable"
                decoy_entry = tarfile.TarInfo("powershell.exe")
                decoy_entry.size = len(decoy)
                tf.addfile(decoy_entry, io.BytesIO(decoy))
            raw = archive.getvalue()

            result_code = worker.run_assignment(
                assignment_id="sealed-win-native-001",
                capsule_b64=base64.b64encode(raw).decode("ascii"),
                capsule_sha256=hashlib.sha256(raw).hexdigest(),
                recipient=recipient,
                timeout_seconds=90,
                out_dir=root / "sealed",
                platform="windows",
            )
            self.assertEqual(0, result_code)
            receipt = json.loads((root / "sealed" / "receipt.json").read_text())
            self.assertEqual("completed", receipt["status"])
            self.assertEqual("windows", receipt["worker_platform"])
            ciphertext = root / "sealed" / "result.age"
            self.assertEqual(hashlib.sha256(ciphertext.read_bytes()).hexdigest(), receipt["sealed_sha256"])
            decrypted = subprocess.run(
                ["age", "--decrypt", "--identity", str(identity), str(ciphertext)],
                check=True, capture_output=True, timeout=30,
            ).stdout
            with tarfile.open(fileobj=io.BytesIO(decrypted), mode="r:gz") as tf:
                marker = tf.extractfile("files/native.txt")
                self.assertIsNotNone(marker)
                self.assertEqual("WINPS51_OK", marker.read().decode().strip())
                metadata = json.loads(tf.extractfile("execution.json").read())
                self.assertEqual("windows", metadata["worker_platform"])
                self.assertEqual(0, metadata["task_exit_code"])
            self.assertFalse((root / "sealed" / "result.tar.gz").exists())


    def test_native_negative_verdicts_are_sealed(self):
        """The Windows body must preserve failure and timeout, not merely green smoke."""
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            identity = root / "identity.txt"
            keygen = subprocess.run(
                ["age-keygen", "-o", str(identity)],
                check=True, capture_output=True, text=True, timeout=30,
            )
            recipient_match = re.search(r"Public key:\s*(age1[0-9a-z]+)", keygen.stderr)
            self.assertIsNotNone(recipient_match)
            recipient = recipient_match.group(1)

            cases = (
                ("exit-nonzero", "exit 17\n", 20, 17, False),
                ("timeout", "Start-Sleep -Seconds 12\n", 1, 124, True),
            )
            for label, script, timeout, expected_rc, expected_timeout in cases:
                with self.subTest(label=label):
                    bundle = io.BytesIO()
                    with tarfile.open(fileobj=bundle, mode="w:gz") as tf:
                        payload = script.encode("utf-8")
                        member = tarfile.TarInfo("run.ps1")
                        member.size = len(payload)
                        tf.addfile(member, io.BytesIO(payload))
                    raw = bundle.getvalue()
                    output = root / label
                    actual_rc = worker.run_assignment(
                        assignment_id="sealed-win-" + label,
                        capsule_b64=base64.b64encode(raw).decode("ascii"),
                        capsule_sha256=hashlib.sha256(raw).hexdigest(),
                        recipient=recipient,
                        timeout_seconds=timeout,
                        out_dir=output,
                        platform="windows",
                    )
                    self.assertEqual(expected_rc, actual_rc)
                    receipt = json.loads((output / "receipt.json").read_text())
                    self.assertEqual("failed", receipt["status"])
                    ciphertext = output / "result.age"
                    self.assertTrue(ciphertext.is_file())
                    self.assertEqual(
                        hashlib.sha256(ciphertext.read_bytes()).hexdigest(),
                        receipt["sealed_sha256"],
                    )
                    plaintext = subprocess.run(
                        ["age", "--decrypt", "--identity", str(identity), str(ciphertext)],
                        check=True, capture_output=True, timeout=30,
                    ).stdout
                    with tarfile.open(fileobj=io.BytesIO(plaintext), mode="r:gz") as tf:
                        metadata = json.loads(tf.extractfile("execution.json").read())
                        self.assertEqual(expected_rc, metadata["task_exit_code"])
                        self.assertEqual(expected_timeout, metadata["timed_out"])
                        self.assertEqual("windows", metadata["worker_platform"])



    def test_native_timeout_kills_descendant_process_tree(self):
        """A spawned PowerShell child must not outlive the sealed task."""
        import time

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            script = root / "spawn-child.ps1"
            marker = root / "child.pid"
            script.write_text(
                "$ErrorActionPreference = 'Stop'\n"
                "$child = Start-Process -FilePath (Join-Path $PSHOME 'powershell.exe') "
                "-ArgumentList '-NoProfile', '-NonInteractive', '-Command', "
                "'Start-Sleep -Seconds 60' -PassThru\n"
                f"$child.Id | Set-Content -LiteralPath '{marker}' -Encoding ASCII\n"
                "Start-Sleep -Seconds 60\n",
                encoding="utf-8",
            )
            with (root / "stdout.txt").open("wb") as stdout_fh, (
                root / "stderr.txt"
            ).open("wb") as stderr_fh:
                rc, timed_out = worker._run_bounded_task(
                    [worker.native_windows_powershell(), "-NoProfile",
                     "-NonInteractive", "-File", str(script)],
                    cwd=root, env=__import__("os").environ.copy(),
                    stdout_fh=stdout_fh, stderr_fh=stderr_fh,
                    timeout_seconds=5, platform="windows",
                )
            self.assertEqual(124, rc)
            self.assertTrue(timed_out)
            self.assertTrue(marker.is_file(), (root / "stderr.txt").read_text(errors="replace"))
            pid = int(marker.read_text().strip())
            self.assertGreater(pid, 0)
            # Job termination is asynchronous for descendants: bounded poll.
            for _ in range(20):
                check = subprocess.run(
                    [worker.native_windows_powershell(), "-NoProfile",
                     "-NonInteractive", "-Command",
                     f"if (Get-Process -Id {pid} -ErrorAction SilentlyContinue) "
                     "{ exit 1 } else { exit 0 }"],
                    capture_output=True, timeout=10,
                )
                if check.returncode == 0:
                    break
                time.sleep(0.25)
            else:
                self.fail(f"spawned child PID {pid} survived task timeout")



if __name__ == "__main__":
    unittest.main()
