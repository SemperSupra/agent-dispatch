import importlib.util
import json
import pathlib
import unittest

SCRIPT = pathlib.Path(__file__).parents[1] / "scripts" / "fritz_qemu_e2_d18_runtime_callsite_observe.py"
SPEC = importlib.util.spec_from_file_location("d18", SCRIPT)
d18 = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(d18)


def obs(target, a0="address_like", d0="aa"):
    return {
        "target": target,
        "args": {
            "a0": {"scalarClass": a0, "memoryDigests": {"8": d0}},
            "a1": {"scalarClass": "address_like", "memoryDigests": {"260": "bb"}},
            "a2": {"scalarClass": "small_positive", "memoryDigests": {}},
            "a3": {"scalarClass": "zero", "memoryDigests": {}},
        },
    }


def call(observations, ready=True):
    return {
        "instrumentation": {"ready": ready, "observations": observations},
    }


class D18Tests(unittest.TestCase):
    def test_scalar_classes(self):
        self.assertEqual(d18.scalar_class(0), "zero")
        self.assertEqual(d18.scalar_class(1), "one")
        self.assertEqual(d18.scalar_class(7), "small_positive")
        self.assertEqual(d18.scalar_class(0x10000), "address_like")

    def test_parse_gdb_stages_accepts_only_known_ordered_markers(self):
        text = (
            "noise\n"
            "FRITZGDBSTAGE:pre_target\n"
            "FRITZGDBSTAGE:post_target\n"
            "FRITZGDBSTAGE:unknown\n"
            "FRITZGDBSTAGE:post_target\n"
        )
        self.assertEqual(
            d18.parse_gdb_stages(text),
            ["pre_target", "post_target"],
        )

    def test_classify_gdb_attach_error_is_sanitized(self):
        self.assertEqual(
            d18.classify_gdb_attach_error("", "Remote communication error. Target disconnected."),
            "remote_disconnected",
        )
        self.assertEqual(
            d18.classify_gdb_attach_error("", "Connection timed out."),
            "connection_timed_out",
        )
        self.assertIsNone(d18.classify_gdb_attach_error("", "unrelated debugger message"))

    def test_parse_gdb_observations_filters_prefix(self):
        text = 'noise\nFRITZOBS:{"target":"_svctl_init","args":{"a0":{},"a1":{},"a2":{},"a3":{}}}\n'
        out = d18.parse_gdb_observations(text)
        self.assertEqual(len(out), 1)
        self.assertEqual(out[0]["target"], "_svctl_init")

    def test_gdb_observation_stops_twice_then_detaches(self):
        text = d18.gdb_command_text(
            pathlib.Path("/tmp/root"),
            25480,
            {"_svctl_init": "*0x1000", "_svctl_send_pkt": "*0x2000"},
        )
        self.assertIn("self.enabled = False", text)
        self.assertIn("return True", text)
        self.assertEqual(text.count("\ncontinue"), 2)
        self.assertIn("\ndetach\n", text)
        self.assertIn("\nquit\n", text)

    def test_attach_control_serialization_is_single_parseable_json_value(self):
        rendered = d18.serialize_attach_control_result({"classification": "typed"})
        self.assertEqual(json.loads(rendered), {"classification": "typed"})
        self.assertTrue(rendered.endswith("\n"))
        self.assertFalse(rendered.endswith("\\n"))


    def test_isolated_interface_names_parses_ip_o_shape(self):
        text = "1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 state UNKNOWN mode DEFAULT\n"
        self.assertEqual(d18.isolated_interface_names(text), ["lo"])


    def test_attach_only_command_has_no_continue_or_breakpoint(self):
        text = d18.gdb_attach_only_command_text(pathlib.Path("/tmp/root"), 25480)
        self.assertIn("target remote 127.0.0.1:25480", text)
        self.assertIn("FRITZGDBSTAGE:pre_target", text)
        self.assertIn("FRITZGDBSTAGE:post_target", text)
        self.assertNotIn("\ncontinue\n", text)
        self.assertNotIn("break", text.lower())

    def test_attach_control_classifies_success_and_rsp_stall(self):
        self.assertEqual(
            d18.classify_attach_control({
                "gdbListenerSeen": True,
                "gdbStages": ["pre_target", "post_target"],
                "gdbExitClass": "zero",
            }),
            "E2_D18_ATTACH_CONTROL_SUCCEEDED_NO_STRACE",
        )
        self.assertEqual(
            d18.classify_attach_control({
                "gdbListenerSeen": True,
                "gdbStages": ["pre_target"],
                "gdbExitClass": "timeout",
            }),
            "E2_D18_ATTACH_CONTROL_RSP_STALL_NO_STRACE",
        )
        self.assertEqual(
            d18.classify_attach_control({
                "gdbListenerSeen": False,
                "gdbStages": [],
                "gdbExitClass": "not_attempted",
            }),
            "E2_D18_ATTACH_CONTROL_LISTENER_NOT_READY",
        )


    def test_status_stability_and_start_difference(self):
        status = [obs("_svctl_init", d0="aa"), obs("_svctl_send_pkt", d0="cc")]
        start = [obs("_svctl_init", d0="dd"), obs("_svctl_send_pkt", d0="cc")]
        runtime = {
            "preStatus": call(status),
            "start": call(start),
            "postStatus": call(status),
        }
        s = d18.summarize_instrumentation(runtime)
        self.assertTrue(s["allCallsInstrumentationReady"])
        self.assertTrue(s["prePostStatusEqual"])
        self.assertTrue(s["startDiffersFromStatus"])
        init = [x for x in s["perTarget"] if x["target"] == "_svctl_init"][0]
        self.assertIn("a0", init["startDifferingArgs"])

    def test_unstable_status_is_not_distinguished(self):
        runtime = {
            "preStatus": call([obs("_svctl_init", d0="aa")]),
            "start": call([obs("_svctl_init", d0="dd")]),
            "postStatus": call([obs("_svctl_init", d0="ee")]),
        }
        s = d18.summarize_instrumentation(runtime)
        self.assertFalse(s["prePostStatusEqual"])

    def test_instrumentation_failure_result_is_sanitized(self):
        original = d18.r6.binary_state_vocabulary
        d18.r6.binary_state_vocabulary = lambda root: {"/bin/svctl": {}, "/bin/supervisor": {}}
        try:
            r = d18.instrumentation_failure_result(pathlib.Path("."), "status", "ctlmgr", "RuntimeError")
        finally:
            d18.r6.binary_state_vocabulary = original
        self.assertFalse(r["instrumentation"]["ready"])
        self.assertEqual(r["instrumentation"]["reason"], "instrumentation_exception")
        self.assertEqual(r["instrumentation"]["errorType"], "RuntimeError")
        self.assertEqual(r["instrumentation"]["errorStage"], "instrumented_svctl_call")
        self.assertFalse(r["instrumentation"]["rawDebuggerOutputPublished"])
        self.assertNotIn("errorMessage", r["instrumentation"])

    def test_summary_preserves_sanitized_failure_stage(self):
        failed = {
            "instrumentation": {
                "ready": False,
                "reason": "instrumentation_exception",
                "errorType": "RuntimeError",
                "errorStage": "callsite_resolution",
                "gdbConnectionSeen": True,
                "breakpointObservationCount": 0,
                "observations": [],
            }
        }
        runtime = {"preStatus": failed, "start": failed, "postStatus": failed}
        s = d18.summarize_instrumentation(runtime)
        self.assertEqual(
            s["callDiagnostics"]["preStatus"]["errorStage"],
            "callsite_resolution",
        )
        self.assertEqual(
            s["callDiagnostics"]["preStatus"]["errorType"],
            "RuntimeError",
        )
        self.assertTrue(
            s["callDiagnostics"]["preStatus"]["gdbConnectionSeen"]
        )
        self.assertEqual(
            s["callDiagnostics"]["preStatus"]["breakpointObservationCount"],
            0,
        )


if __name__ == "__main__":
    unittest.main()
