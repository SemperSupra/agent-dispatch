import importlib.util
import pathlib
import unittest

SCRIPT = pathlib.Path(__file__).parents[1] / "scripts" / "fritz_qemu_e2_d11_protocol_deps.py"
SPEC = importlib.util.spec_from_file_location("d11", SCRIPT)
d11 = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(d11)


class D11Tests(unittest.TestCase):
    def test_classify_prefers_size_slice(self):
        slice_={"objects":{
            "/lib/libsvctl.so.1":{"derived":{
                "callsiteHas8ByteAdjacency":True,
                "callsiteHas260ByteAdjacency":False,
                "ioSymbolCount":1,
                "controlSymbolCount":1,
            }}
        }}
        self.assertEqual(d11.classify(slice_), "E2_D11_PROTOCOL_LIBRARY_SIZE_SLICE_RECOVERED")

    def test_classify_io_surface(self):
        slice_={"objects":{
            "/lib/libsvctl.so.1":{"derived":{
                "callsiteHas8ByteAdjacency":False,
                "callsiteHas260ByteAdjacency":False,
                "ioSymbolCount":2,
                "controlSymbolCount":1,
            }}
        }}
        self.assertEqual(d11.classify(slice_), "E2_D11_PROTOCOL_LIBRARY_IO_SURFACE_RECOVERED")

    def test_no_library_is_typed_negative(self):
        self.assertEqual(
            d11.classify({"objects":{"/bin/svctl":{"derived":{}}}}),
            "E2_D11_PROTOCOL_LIBRARIES_NOT_RESOLVED",
        )


if __name__ == "__main__":
    unittest.main()
