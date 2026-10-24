import importlib.util,json,os,pathlib,tempfile,unittest
ROOT=pathlib.Path(__file__).resolve().parents[1]
def load(name,path):
    spec=importlib.util.spec_from_file_location(name,ROOT/path); mod=importlib.util.module_from_spec(spec); assert spec.loader; spec.loader.exec_module(mod); return mod
VM=load("p5vm",pathlib.Path("scripts/github_runner_firecracker_p5_vm.py"))
RV=load("p5rv",pathlib.Path("scripts/github_runner_firecracker_p5_rendezvous.py"))

class FirecrackerP5Tests(unittest.TestCase):
    def test_guest_fixture_has_long_lived_markers(self):
        source=VM.INIT_SOURCE.read_text()
        self.assertIn("FIRECRACKER_P5_READY",source)
        self.assertIn("FIRECRACKER_P5_HEARTBEAT",source)
        self.assertIn("counter<120",source)

    def test_validate_requires_both_live_witnesses_and_offer_binding(self):
        old=os.environ.get("GITHUB_RUN_ID"); os.environ["GITHUB_RUN_ID"]="123"
        try:
            with tempfile.TemporaryDirectory() as td:
                root=pathlib.Path(td); offer=root/"offer.json"; status=root/"producer.json"; ack=root/"ack.json"
                offer.write_text('{"alive":true}\n')
                import hashlib
                h=hashlib.sha256(offer.read_bytes()).hexdigest()
                status.write_text(json.dumps({"alive":True,"ready_observed":True}))
                ack.write_text(json.dumps({"run_id":"123","offer_sha256":h,"consumer_status":{"alive":True,"ready_observed":True}}))
                result=RV.validate(offer,ack,status)
            self.assertEqual(result["classification"],"SUPPORTED")
        finally:
            if old is None: os.environ.pop("GITHUB_RUN_ID",None)
            else: os.environ["GITHUB_RUN_ID"]=old

if __name__=="__main__":unittest.main()
