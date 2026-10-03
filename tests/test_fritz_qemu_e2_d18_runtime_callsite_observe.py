import importlib.util
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

    def test_parse_gdb_observations_filters_prefix(self):
        text = 'noise\nFRITZOBS:{"target":"_svctl_init","args":{"a0":{},"a1":{},"a2":{},"a3":{}}}\n'
        out = d18.parse_gdb_observations(text)
        self.assertEqual(len(out), 1)
        self.assertEqual(out[0]["target"], "_svctl_init")

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


if __name__ == "__main__":
    unittest.main()
