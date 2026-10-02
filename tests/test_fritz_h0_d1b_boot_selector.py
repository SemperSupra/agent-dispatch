import importlib.util
import io
import pathlib
import tarfile
import tempfile
import unittest

SCRIPT = pathlib.Path(__file__).parents[1] / "scripts" / "fritz_h0_d1b_boot_selector.py"
SPEC = importlib.util.spec_from_file_location("d1b", SCRIPT)
d1b = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(d1b)


class D1bTests(unittest.TestCase):
    def make_tar(self):
        td = tempfile.TemporaryDirectory()
        p = pathlib.Path(td.name) / "x.tar.gz"
        with tarfile.open(p, "w:gz") as tf:
            samples = {
                "sources/kernel/linux/arch/mips/lantiq/grx500/prom.c": b"prom environment linux_fs_start grx500\n",
                "sources/kernel/linux/drivers/char/tffs/env.c": b"tffs environment nand partition\n",
                "sources/kernel/linux/drivers/mtd/core.c": b"mtd partition nand\n",
                "README": b"linux_fs_start should be ignored by path scope\n",
            }
            for name,data in samples.items():
                ti=tarfile.TarInfo(name)
                ti.size=len(data)
                tf.addfile(ti, io.BytesIO(data))
        return td,p

    def test_targeted_reduction(self):
        td,p=self.make_tar()
        try:
            r=d1b.scan(p)
            self.assertEqual(r["matchingFileCount"],3)
            paths=[x["path"] for x in r["files"]]
            self.assertNotIn("README", paths)
            prom=next(x for x in r["files"] if x["path"].endswith("prom.c"))
            self.assertEqual(prom["domain"],"grx500-boot")
            self.assertIn("linux_fs_start",prom["tokens"])
            self.assertTrue(any(x["path"].endswith("prom.c") for x in r["bridgeFiles"]))
        finally:
            td.cleanup()

    def test_domain_classification(self):
        self.assertEqual(d1b.domain_for("sources/kernel/linux/drivers/char/tffs/env.c"),"tffs")
        self.assertEqual(d1b.domain_for("sources/kernel/linux/drivers/mtd/x.c"),"mtd")


if __name__=="__main__":
    unittest.main()
