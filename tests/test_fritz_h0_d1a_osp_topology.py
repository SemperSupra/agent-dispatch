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
    def test_interesting_path(self):
        self.assertTrue(d1.interesting_path("linux/arch/mips/boot/dts/grx5-7590.dts"))
        self.assertFalse(d1.interesting_path("packages/zlib/README"))

    def test_fixed_marker_scan(self):
        x = d1.scan_fixed_markers(b"foo linux_fs_start mtdparts tffs bar")
        self.assertTrue(x["linux_fs_start"]["present"])
        self.assertTrue(x["mtdparts"]["present"])
        self.assertTrue(x["tffs"]["present"])

    def test_census_finds_direct_dts_and_nested(self):
        with tempfile.TemporaryDirectory() as td:
            p = pathlib.Path(td) / "x.tar.gz"
            with tarfile.open(p, "w:gz") as tf:
                data = b"linux_fs_start mtdparts"
                info = tarfile.TarInfo("linux/arch/mips/boot/dts/grx5-7590.dts")
                info.size = len(data)
                tf.addfile(info, io.BytesIO(data))
                nested = b"abc"
                info2 = tarfile.TarInfo("sources/linux-kernel.tar.xz")
                info2.size = len(nested)
                tf.addfile(info2, io.BytesIO(nested))
            x = d1.census(p, 20)
            self.assertEqual(x["directDtsDtsiCount"], 1)
            self.assertEqual(x["classification"], "DIRECT_SOURCE_TOPOLOGY_VISIBLE")
            self.assertEqual(len(x["interestingNestedArchives"]), 1)


if __name__ == "__main__":
    unittest.main()
