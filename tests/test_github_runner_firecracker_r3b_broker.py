#!/usr/bin/env python3
from __future__ import annotations

import importlib.util
import json
import pathlib
import sys
import unittest

ROOT=pathlib.Path(__file__).resolve().parents[1]
SCRIPT=ROOT/"scripts/github_runner_firecracker_r3b_broker.py"
spec=importlib.util.spec_from_file_location("r3b",SCRIPT)
r3b=importlib.util.module_from_spec(spec)
assert spec and spec.loader
sys.modules["r3b"]=r3b
spec.loader.exec_module(r3b)


class R3bBrokerTests(unittest.TestCase):
    def test_deterministic_backend_is_bounded_and_stable(self):
        req={"operation":"classify","profile":"deterministic-v0","input":"hello"}
        a=r3b.deterministic_backend(req)
        b=r3b.deterministic_backend(req)
        self.assertEqual(a,b)
        self.assertEqual(a["profile"],"deterministic-v0")
        with self.assertRaises(ValueError):
            r3b.deterministic_backend({**req,"url":"https://example.com"})
        with self.assertRaises(ValueError):
            r3b.deterministic_backend({**req,"profile":"arbitrary"})

    def test_capability_is_single_use(self):
        state=r3b.BrokerState("secret",ttl_seconds=60)
        body=json.dumps(
            {"operation":"classify","profile":"deterministic-v0","input":"hello"},
            sort_keys=True,separators=(",",":"),
        ).encode()
        first,payload=state.handle(authorization="Bearer secret",body=body)
        second,_=state.handle(authorization="Bearer secret",body=body)
        self.assertEqual(first,200)
        self.assertEqual(second,409)
        self.assertEqual(state.accepted,1)
        self.assertEqual(state.replay_rejected,1)
        self.assertEqual(state.rejected,0)
        self.assertNotIn(b"secret",payload)

    def test_wrong_capability_never_consumes_valid_one(self):
        state=r3b.BrokerState("secret",ttl_seconds=60)
        body=b'{"input":"hello","operation":"classify","profile":"deterministic-v0"}'
        status,_=state.handle(authorization="Bearer wrong",body=body)
        self.assertEqual(status,401)
        self.assertEqual(state.accepted,0)
        self.assertEqual(state.rejected,1)

    def test_guest_source_has_no_provider_or_generic_proxy_surface(self):
        source=(ROOT/"experiments/firecracker/guest/r3b-broker-probe.py").read_text()
        self.assertNotIn("api.openai",source)
        self.assertNotIn("anthropic",source.lower())
        self.assertNotIn("CONNECT",source)
        self.assertIn("/v1/infer",source)
        self.assertNotIn("print(token",source)

    def test_workflow_and_script_remain_credential_free(self):
        workflow=(ROOT/".github/workflows/github-runner-firecracker-r3b-broker.yml").read_text()
        source=SCRIPT.read_text()
        # GitHub secret interpolation is prohibited. The Python source deliberately
        # uses the stdlib secrets module only to mint the per-run bearer capability.
        self.assertNotIn("secrets.",workflow)
        self.assertIn("secrets.token_urlsafe",source)
        for needle in ("OPENAI_API_KEY","ANTHROPIC_API_KEY","GEMINI_API_KEY","NVIDIA_API_KEY"):
            self.assertNotIn(needle,workflow)
            self.assertNotIn(needle,source)


if __name__=="__main__":
    unittest.main()
