import importlib.util
import json
import pathlib
import tempfile
import unittest
from unittest import mock

ROOT = pathlib.Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location(
    "github_runner_firecracker_f1_boot",
    ROOT / "scripts" / "github_runner_firecracker_f1_boot.py",
)
MOD = importlib.util.module_from_spec(SPEC)
assert SPEC.loader
SPEC.loader.exec_module(MOD)


class FirecrackerF1BootTests(unittest.TestCase):
    def test_kernel_manifest_is_exactly_pinned(self):
        manifest = json.loads(
            (ROOT / "experiments" / "firecracker" / "guest-kernel-6.18.48-x86_64.json").read_text()
        )
        self.assertEqual(manifest["kernel_version"], "6.18.48")
        self.assertEqual(
            manifest["kernel_sha256"],
            "9204218e8bcca6ac23848d74f45df2eb19d7f31e8277840a7d145a0df8b078d2",
        )
        self.assertEqual(manifest["kernel_size_bytes"], 27846792)

    def test_newc_entry_has_magic_and_alignment(self):
        record = MOD._newc_entry(
            "init",
            mode=0o100755,
            data=b"abc",
            ino=1,
        )
        self.assertTrue(record.startswith(b"070701"))
        self.assertEqual(len(record) % 4, 0)
        self.assertIn(b"init\0", record)
        self.assertIn(b"abc", record)

    def test_initramfs_contains_console_init_and_trailer(self):
        with tempfile.TemporaryDirectory() as td:
            root = pathlib.Path(td)
            init = root / "init"
            init.write_bytes(b"ELF-placeholder")
            out = root / "initrd.cpio"
            MOD._build_initramfs(init, out)
            payload = out.read_bytes()
        self.assertIn(b"dev/console\0", payload)
        self.assertIn(b"init\0", payload)
        self.assertIn(b"TRAILER!!!\0", payload)

    def test_config_is_networkless_and_diskless(self):
        with tempfile.TemporaryDirectory() as td:
            root = pathlib.Path(td)
            kernel = root / "vmlinux"
            initrd = root / "initrd.cpio"
            output = root / "config.json"
            kernel.write_bytes(b"k")
            initrd.write_bytes(b"i")
            config = MOD._build_config(kernel, initrd, output)
        self.assertEqual(config["drives"], [])
        self.assertEqual(config["network-interfaces"], [])
        self.assertEqual(config["machine-config"]["vcpu_count"], 1)
        self.assertEqual(config["machine-config"]["mem_size_mib"], 128)
        self.assertIn("console=ttyS0", config["boot-source"]["boot_args"])

    def test_boot_oracle_requires_nonce_and_clean_exit(self):
        with (
            mock.patch.object(MOD.shutil, "which", side_effect=lambda n: f"/usr/bin/{n}"),
            mock.patch.object(
                MOD.f0,
                "_run",
                return_value=(
                    0,
                    MOD.NONCE + "\nFirecracker exiting successfully. exit_code=0",
                    "",
                ),
            ),
        ):
            result = MOD._run_firecracker(pathlib.Path("/tmp/firecracker"), pathlib.Path("/tmp/config"))
        self.assertTrue(result["ok"])
        self.assertEqual(result["classification"], "SUPPORTED")

    def test_boot_oracle_rejects_clean_exit_without_guest_nonce(self):
        with (
            mock.patch.object(MOD.shutil, "which", side_effect=lambda n: f"/usr/bin/{n}"),
            mock.patch.object(
                MOD.f0,
                "_run",
                return_value=(0, "Firecracker exiting successfully. exit_code=0", ""),
            ),
        ):
            result = MOD._run_firecracker(pathlib.Path("/tmp/firecracker"), pathlib.Path("/tmp/config"))
        self.assertFalse(result["ok"])
        self.assertEqual(result["classification"], "ORACLE_FAILURE")


if __name__ == "__main__":
    unittest.main()
