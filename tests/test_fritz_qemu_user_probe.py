import importlib.util
import io
import pathlib
import tarfile
import tempfile
import unittest

SCRIPT = (
    pathlib.Path(__file__).resolve().parents[1]
    / "scripts"
    / "fritz_qemu_user_probe.py"
)
spec = importlib.util.spec_from_file_location("fritz_probe", SCRIPT)
probe = importlib.util.module_from_spec(spec)
assert spec.loader
spec.loader.exec_module(probe)


def fake_elf(*, endian: str, machine: int = 8, elf_class: int = 1) -> bytes:
    b = bytearray(64)
    b[0:4] = b"\x7fELF"
    b[4] = elf_class
    b[5] = 1 if endian == "little" else 2
    b[18:20] = machine.to_bytes(2, endian)
    return bytes(b)


class ProbeTests(unittest.TestCase):
    def test_parse_big_endian_mips(self):
        with tempfile.TemporaryDirectory() as td:
            p = pathlib.Path(td) / "mips"
            p.write_bytes(fake_elf(endian="big"))
            got = probe.parse_elf_header(p)
            self.assertEqual(got["machineName"], "MIPS")
            self.assertEqual(got["endian"], "big")
            self.assertEqual(probe.qemu_for_header(got), "qemu-mips-static")

    def test_parse_little_endian_mips(self):
        with tempfile.TemporaryDirectory() as td:
            p = pathlib.Path(td) / "mipsel"
            p.write_bytes(fake_elf(endian="little"))
            got = probe.parse_elf_header(p)
            self.assertEqual(got["machine"], 8)
            self.assertEqual(got["endian"], "little")
            self.assertEqual(probe.qemu_for_header(got), "qemu-mipsel-static")

    def test_select_busybox_fallback_is_bounded(self):
        with tempfile.TemporaryDirectory() as td:
            root = pathlib.Path(td)
            (root / "bin").mkdir()
            (root / "bin" / "busybox").write_bytes(
                fake_elf(endian="big")
            )
            candidate, args, header = probe.select_harmless_candidate(root)
            self.assertEqual(
                candidate.relative_to(root).as_posix(),
                "bin/busybox",
            )
            self.assertEqual(args, ["true"])
            self.assertEqual(header["machine"], 8)

    def test_tar_path_traversal_is_rejected(self):
        with tempfile.TemporaryDirectory() as td:
            p = pathlib.Path(td) / "bad.tar"
            with tarfile.open(p, "w") as tf:
                info = tarfile.TarInfo("../escape")
                payload = b"x"
                info.size = len(payload)
                tf.addfile(info, io.BytesIO(payload))
            with self.assertRaises(ValueError):
                probe._safe_tar_members(p)


if __name__ == "__main__":
    unittest.main()
