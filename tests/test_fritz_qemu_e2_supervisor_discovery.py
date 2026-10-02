import importlib.util
import pathlib
import unittest

SCRIPT = (
    pathlib.Path(__file__).resolve().parents[1]
    / "scripts"
    / "fritz_qemu_e2_supervisor_discovery.py"
)
spec = importlib.util.spec_from_file_location("fritz_e2_sv", SCRIPT)
sv = importlib.util.module_from_spec(spec)
assert spec.loader
spec.loader.exec_module(sv)


class SupervisorDiscoveryTests(unittest.TestCase):
    def test_marker_hits(self):
        self.assertEqual(
            sv.marker_hits(b"svctl start ctlmgr via supervisor"),
            ["ctlmgr", "svctl", "supervisor"],
        )

    def test_safe_service_relation_start(self):
        got = sv.service_command_relations(
            "svctl start ctlmgr\n",
            "/etc/init.d/rc.net",
        )
        self.assertEqual(got, [{
            "source": "/etc/init.d/rc.net",
            "controller": "svctl",
            "verb": "start",
            "service": "ctlmgr",
        }])

    def test_safe_service_relation_reversed_form(self):
        got = sv.service_command_relations(
            "svctl ctlmgr restart\n",
            "/etc/init.d/x",
        )
        self.assertEqual(got[0]["verb"], "restart")

    def test_exec_relation(self):
        got = sv.service_command_relations(
            "exec /usr/bin/ctlmgr\n",
            "/etc/init.d/rc.ctlmgr",
        )
        self.assertEqual(got[0]["controller"], "shell")
        self.assertEqual(got[0]["verb"], "exec")

    def test_unrelated_line_not_promoted(self):
        self.assertEqual(
            sv.service_command_relations(
                "echo ctlmgr; echo svctl\n",
                "/etc/init.d/x",
            ),
            [],
        )


if __name__ == "__main__":
    unittest.main()
