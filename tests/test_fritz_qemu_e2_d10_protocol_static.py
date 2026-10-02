import importlib.util
import io
import pathlib
import tarfile
import tempfile
import unittest

SCRIPT = pathlib.Path(__file__).parents[1] / "scripts" / "fritz_qemu_e2_d10_protocol_static.py"
SPEC = importlib.util.spec_from_file_location("d10", SCRIPT)
d10 = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(d10)


class D10Tests(unittest.TestCase):
    def test_osp_generic_supervisor_word_is_not_source_surface(self):
        with tempfile.TemporaryDirectory() as td:
            archive = pathlib.Path(td) / "osp.tar.gz"
            with tarfile.open(archive, "w:gz") as tf:
                data = b"CPU enters supervisor mode"
                info = tarfile.TarInfo("sources/kernel/linux/example.c")
                info.size = len(data)
                tf.addfile(info, io.BytesIO(data))
            got = d10.osp_fixed_token_coverage(archive)
        self.assertFalse(got["sourceSurfaceFound"])
        self.assertEqual(got["genericSupervisorContentMatchCount"], 1)
        self.assertEqual(got["strongContentTokenMatches"], [])

    def test_osp_svctl_is_strong_source_surface(self):
        with tempfile.TemporaryDirectory() as td:
            archive = pathlib.Path(td) / "osp.tar.gz"
            with tarfile.open(archive, "w:gz") as tf:
                data = b"svctl protocol client"
                info = tarfile.TarInfo("sources/example.c")
                info.size = len(data)
                tf.addfile(info, io.BytesIO(data))
            got = d10.osp_fixed_token_coverage(archive)
        self.assertTrue(got["sourceSurfaceFound"])
        self.assertEqual(got["strongContentTokenMatches"][0]["tokens"], ["svctl"])

    def test_fixed_token_counts_are_bounded(self):
        data = b"start status ctlmgr supervisor supervisor.ctrl.socket restart"
        got = d10.fixed_token_counts(data)
        self.assertEqual(got["start"], 1)
        self.assertEqual(got["status"], 1)
        self.assertEqual(got["ctlmgr"], 1)
        self.assertEqual(got["supervisor.ctrl.socket"], 1)

    def test_fixed_size_hits(self):
        asm = "li a2,260"
        got = d10.fixed_size_hits(asm)
        self.assertEqual(got, [{"bytes": 260, "meaning": "r9SecondRequestOrResponseChunkBytes"}])
        got = d10.fixed_size_hits("addiu a2,zero,0x8")
        self.assertEqual(got, [{"bytes": 8, "meaning": "r9FirstRequestChunkBytes"}])

    def test_callsite_summary_only_emits_fixed_metadata(self):
        disasm = """
00400100:\t24060008 \tli\ta2,8
00400104:\t0320f809 \tjalr\tt9
00400108:\t00000000 \tnop
            R_MIPS_JALR sendto
0040010c:\t24060104 \tli\ta2,260
00400110:\t0320f809 \tjalr\tt9
            R_MIPS_JALR read
"""
        got = d10.callsite_fixed_size_summary(disasm, radius=3)
        self.assertTrue(any(x["symbol"] == "sendto" for x in got))
        send = next(x for x in got if x["symbol"] == "sendto")
        self.assertTrue(any(x["bytes"] == 8 for x in send["fixedSizesNearby"]))
        read = next(x for x in got if x["symbol"] == "read")
        self.assertTrue(any(x["bytes"] == 260 for x in read["fixedSizesNearby"]))
        self.assertNotIn("00400100", str(got))

    def test_classification_is_typed_not_acceptance_of_semantics(self):
        svctl = {
            "derived": {
                "fixedVerbTokenCount": 5,
                "callsiteHas8ByteAdjacency": False,
                "callsiteHas260ByteAdjacency": False,
            }
        }
        self.assertEqual(
            d10.classify(svctl, {"sourceSurfaceFound": False}),
            "E2_D10_STATIC_PROTOCOL_SURFACE_PARTIAL",
        )
        self.assertEqual(
            d10.classify(svctl, {"sourceSurfaceFound": True}),
            "E2_D10_SOURCE_SURFACE_FOUND_BINARY_CALLSITE_PARTIAL",
        )


if __name__ == "__main__":
    unittest.main()
