import importlib.util
import pathlib
import unittest

SCRIPT = pathlib.Path(__file__).resolve().parents[1] / "scripts" / "fritz_qemu_e2_startup_semantics.py"
spec = importlib.util.spec_from_file_location("startup", SCRIPT)
m = importlib.util.module_from_spec(spec)
assert spec.loader
spec.loader.exec_module(m)


class StartupSemanticsTests(unittest.TestCase):
    def test_supervisor_invocation_classifies_unknown(self):
        got = m.supervisor_invocations(
            '/bin/supervisor -f /etc/sv.conf secret-token\n',
            '/etc/init.d/rc.net',
        )[0]
        self.assertEqual(got["args"][0], {"kind":"option","value":"-f"})
        self.assertEqual(got["args"][1], {"kind":"absolute_path","value":"/etc/sv.conf"})
        self.assertEqual(got["args"][2]["kind"], "opaque")
        self.assertNotIn("secret-token", str(got))

    def test_variable_flow(self):
        text = 'srv=ctlmgr\nsvctl start "$srv"\n'
        a = m.ctlmgr_assignment_facts(text, "/etc/init.d/x")
        c = m.svctl_consumers(text, "/etc/init.d/x")
        r = m.correlate(a, c)
        self.assertEqual(r[0]["service"], "ctlmgr")
        self.assertEqual(r[0]["verb"], "start")
        self.assertEqual(r[0]["evidenceKind"], "same-file-variable-flow")

    def test_for_list_flow(self):
        text = 'for srv in multid ctlmgr dsld; do\n svctl restart $srv\ndone\n'
        a = m.ctlmgr_assignment_facts(text, "/etc/init.d/x")
        c = m.svctl_consumers(text, "/etc/init.d/x")
        r = m.correlate(a, c)
        self.assertEqual(r[0]["bindingKind"], "for-list")
        self.assertFalse(r[0]["exactCtlmgrOnly"])

    def test_literal_relation(self):
        c = m.svctl_consumers("svctl start ctlmgr\n", "/etc/init.d/x")
        r = m.correlate([], c)
        self.assertEqual(r[0]["evidenceKind"], "literal")

    def test_related_paths_only_relevant_lines(self):
        got = m.fixed_related_paths(
            'echo /etc/ignore\n/bin/supervisor /etc/supervisor.conf\n',
            '/etc/init.d/x',
        )
        self.assertEqual(got, [
            {"source":"/etc/init.d/x","path":"/bin/supervisor"},
            {"source":"/etc/init.d/x","path":"/etc/supervisor.conf"},
        ])


if __name__ == "__main__":
    unittest.main()
