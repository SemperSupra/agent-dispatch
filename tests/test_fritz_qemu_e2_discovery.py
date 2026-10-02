import importlib.util
import pathlib
import tempfile
import unittest

SCRIPT = (
    pathlib.Path(__file__).resolve().parents[1]
    / "scripts"
    / "fritz_qemu_e2_discovery.py"
)
spec = importlib.util.spec_from_file_location("fritz_e2", SCRIPT)
e2 = importlib.util.module_from_spec(spec)
assert spec.loader
spec.loader.exec_module(e2)


class E2DiscoveryTests(unittest.TestCase):
    def test_marker_hits_are_fixed_and_bounded(self):
        data = b"prefix login_sid.lua suffix /webservices/"
        self.assertEqual(
            e2.marker_hits(data),
            ["login_sid_lua", "webservices_path"],
        )

    def test_path_token_hits(self):
        self.assertIn("http", e2.path_token_hits("/usr/sbin/httpd"))
        self.assertIn("ctlmgr", e2.path_token_hits("/usr/bin/ctlmgr"))

    def test_init_like_paths(self):
        self.assertTrue(e2.is_init_like("etc/init.d/rc.web"))
        self.assertTrue(e2.is_init_like("etc/rc.S/foo"))
        self.assertFalse(e2.is_init_like("usr/www/login_sid.lua"))

    def test_rank_prefers_marker_over_path_token(self):
        items = [
            {
                "path": "/usr/bin/http-helper",
                "kind": "elf",
                "reasons": ["path-token:http"],
                "elf": {"machineName": "MIPS"},
            },
            {
                "path": "/usr/bin/service-x",
                "kind": "elf",
                "reasons": ["marker:login_sid_lua"],
                "elf": {"machineName": "MIPS"},
            },
        ]
        ranked = e2.rank_candidates(items, [])
        self.assertEqual(ranked[0]["path"], "/usr/bin/service-x")
        self.assertGreater(ranked[0]["score"], ranked[1]["score"])

    def test_init_reference_adds_evidence(self):
        with tempfile.TemporaryDirectory() as td:
            root = pathlib.Path(td)
            p = root / "etc" / "init.d"
            p.mkdir(parents=True)
            (p / "rc.web").write_text(
                "/usr/bin/websrv --daemon\n",
                encoding="utf-8",
            )
            init_items = [{
                "path": "/etc/init.d/rc.web",
                "kind": "init-text",
            }]
            edges = e2.init_reference_edges(
                root,
                init_items,
                {"websrv": "/usr/bin/websrv"},
            )
            self.assertEqual(edges, [{
                "source": "/etc/init.d/rc.web",
                "target": "/usr/bin/websrv",
                "reference": "websrv",
            }])


if __name__ == "__main__":
    unittest.main()
