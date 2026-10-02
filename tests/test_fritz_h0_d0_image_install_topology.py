import importlib.util
import pathlib
import unittest

SCRIPT = pathlib.Path(__file__).resolve().parents[1] / "scripts" / "fritz_h0_d0_image_install_topology.py"
spec = importlib.util.spec_from_file_location("fritz_h0_d0", SCRIPT)
h0 = importlib.util.module_from_spec(spec)
assert spec.loader
spec.loader.exec_module(h0)


class H0D0Tests(unittest.TestCase):
    def test_shape_classic(self):
        x = h0.classify_shape(["var/tmp/kernel.image", "var/tmp/filesystem.image", "var/install"])
        self.assertEqual(x["classification"], "classic-kernel-filesystem")

    def test_shape_dual(self):
        x = h0.classify_shape([
            "var/remote/var/tmp/kernel.image",
            "var/remote/var/tmp/filesystem.image",
            "var/remote/var/tmp/x86/kernel.image",
            "var/remote/var/tmp/x86/filesystem.image",
        ])
        self.assertEqual(x["classification"], "dual-architecture-components")

    def test_shape_uimg_precedence(self):
        x = h0.classify_shape([
            "var/firmware-update.uimg",
            "var/tmp/kernel.image",
            "var/tmp/filesystem.image",
        ])
        self.assertEqual(x["classification"], "uimg-container")

    def test_install_scan_only_emits_fixed_metadata(self):
        raw = (
            b"secret arbitrary proprietary line\n"
            b"quote SETENV linux_fs_start 1\n"
            b"write /dev/mtd3 mtd4 kernel.image filesystem.image\n"
        )
        x = h0.scan_install_bytes(raw)
        self.assertTrue(x["fixedMarkers"]["linux_fs_start"]["present"])
        self.assertIn("mtd4", [t.lower() for t in x["mtdTokens"]])
        self.assertIn("/dev/mtd3", [t.lower() for t in x["devMtdTokens"]])
        self.assertNotIn("secret", str(x).lower())


if __name__ == "__main__":
    unittest.main()
