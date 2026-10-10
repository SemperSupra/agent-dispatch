import importlib.util
import pathlib
import unittest

ROOT=pathlib.Path(__file__).resolve().parents[1]

def load(name,path):
    spec=importlib.util.spec_from_file_location(name,ROOT/path)
    mod=importlib.util.module_from_spec(spec)
    assert spec.loader
    spec.loader.exec_module(mod)
    return mod

PRODUCER=load("p4producer",pathlib.Path("scripts/github_runner_firecracker_p4_producer.py"))
CONSUMER=load("p4consumer",pathlib.Path("scripts/github_runner_firecracker_p4_consumer.py"))

class FirecrackerP4Tests(unittest.TestCase):
    def test_schemas_are_distinct(self):
        self.assertEqual(PRODUCER.SCHEMA,"firecracker-p4-producer/v1")
        self.assertEqual(CONSUMER.SCHEMA,"firecracker-p4-consumer/v1")

    def test_p3_guest_fixture_is_reused(self):
        self.assertTrue(PRODUCER.p3.INIT_SOURCE.exists())
        source=PRODUCER.p3.INIT_SOURCE.read_text()
        self.assertIn("FIRECRACKER_P3_READY",source)
        self.assertIn("FIRECRACKER_P3_HEARTBEAT",source)

if __name__=="__main__":
    unittest.main()
