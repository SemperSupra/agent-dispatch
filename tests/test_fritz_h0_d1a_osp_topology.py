import importlib.util
import io
import pathlib
import tarfile
import tempfile
import unittest

SCRIPT = pathlib.Path(__file__).resolve().parents[1] / "scripts" / "fritz_h0_d1a_osp_topology.py"
spec = importlib.util.spec_from_file_location("fritz_h0_d1a", SCRIPT)
d1 = importlib.util.module_from_spec(spec)
assert spec.loader
spec.loader.exec_module(d1)


class D1ATests(unittest.TestCase):
    def test_path_categories_are_specific(self):
        self.assertIn(
            "mipsDts",
            d1.categories_for_path("sources/kernel/linux/arch/mips/boot/dts/grx5-7590.dts"),
        )
        self.assertIn(
            "targetNamed",
            d1.categories_for_path("sources/kernel/linux/arch/mips/boot/dts/grx5-7590.dts"),
        )
        self.assertIn(
            "mtd",
            d1.categories_for_path("sources/kernel/linux/drivers/mtd/mtdpart.c"),
        )
        self.assertEqual(
            d1.categories_for_path("sources/apparmor/kernel-patches/README"),
            [],
        )

    def test_token_scan_uses_boundaries(self):
        x = d1.scan_tokens(b"EVA evaluation linux_fs_start mtdparts tffs GRX550")
        self.assertEqual(x["eva"]["count"], 1)
        self.assertTrue(x["linux_fs_start"]["present"])
        self.assertTrue(x["mtdparts"]["present"])
        self.assertTrue(x["tffs"]["present"])
        self.assertTrue(x["grx550"]["present"])

    def test_census_separates_categories(self):
        with tempfile.TemporaryDirectory() as td:
            p = pathlib.Path(td) / "x.tar.gz"
            with tarfile.open(p, "w:gz") as tf:
                data = b"GRX550 linux_fs_start mtdparts"
                info = tarfile.TarInfo(
                    "sources/kernel/linux/arch/mips/boot/dts/grx5-7590.dts"
                )
                info.size = len(data)
                tf.addfile(info, io.BytesIO(data))

                mtd = b"tffs mtdparts"
                info2 = tarfile.TarInfo(
                    "sources/kernel/linux/drivers/mtd/avm/tffs.c"
                )
                info2.size = len(mtd)
                tf.addfile(info2, io.BytesIO(mtd))

                noise = b"EVA evaluation"
                info3 = tarfile.TarInfo(
                    "sources/apparmor/kernel-patches/README"
                )
                info3.size = len(noise)
                tf.addfile(info3, io.BytesIO(noise))

            x = d1.census(p, 20)
            self.assertEqual(x["classification"], "TARGETED_DIRECT_SOURCE_VISIBLE")
            self.assertEqual(len(x["categories"]["mipsDts"]), 1)
            self.assertEqual(len(x["categories"]["mtd"]), 1)
            self.assertEqual(len(x["categories"]["targetNamed"]), 2)
            self.assertEqual(len(x["categories"]["bootEnvironment"]), 0)


if __name__ == "__main__":
    unittest.main()
