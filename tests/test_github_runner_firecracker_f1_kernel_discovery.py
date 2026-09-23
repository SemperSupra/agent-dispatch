import importlib.util
import pathlib
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location(
    "github_runner_firecracker_f1_kernel_discovery",
    ROOT / "scripts" / "github_runner_firecracker_f1_kernel_discovery.py",
)
MOD = importlib.util.module_from_spec(SPEC)
assert SPEC.loader
SPEC.loader.exec_module(MOD)


class FirecrackerF1KernelDiscoveryTests(unittest.TestCase):
    def test_select_latest_ci_prefix(self):
        prefixes = [
            "firecracker-ci/20260901-old/",
            "firecracker-ci/20260920-new/",
            "other/",
        ]
        self.assertEqual(
            MOD._select_latest_ci_prefix(prefixes),
            "firecracker-ci/20260920-new/",
        )

    def test_select_latest_kernel_semantically(self):
        ci = "firecracker-ci/20260920-build/"
        keys = [
            f"{ci}x86_64/vmlinux-6.1.200",
            f"{ci}x86_64/vmlinux-6.18.10",
            f"{ci}x86_64/vmlinux-6.18.9",
            f"{ci}aarch64/vmlinux-6.18.99",
        ]
        self.assertEqual(
            MOD._select_latest_kernel(keys, ci, "x86_64"),
            f"{ci}x86_64/vmlinux-6.18.10",
        )

    def test_parse_s3_common_prefixes_and_keys(self):
        xml = b"""<?xml version="1.0" encoding="UTF-8"?>
<ListBucketResult xmlns="http://s3.amazonaws.com/doc/2006-03-01/">
  <Contents><Key>firecracker-ci/20260920-build/x86_64/vmlinux-6.18.10</Key></Contents>
  <CommonPrefixes><Prefix>firecracker-ci/20260920-build/</Prefix></CommonPrefixes>
</ListBucketResult>"""
        self.assertEqual(
            MOD._parse_common_prefixes(xml),
            ["firecracker-ci/20260920-build/"],
        )
        self.assertEqual(
            MOD._parse_keys(xml),
            ["firecracker-ci/20260920-build/x86_64/vmlinux-6.18.10"],
        )

    def test_kernel_version_rejects_non_kernel_key(self):
        with self.assertRaises(ValueError):
            MOD._kernel_version("not-a-kernel")


if __name__ == "__main__":
    unittest.main()
