import json, os, pathlib, tempfile, unittest
from unittest import mock
from scripts import gha_workload_request as gwr

def valid_request():
    return {
        "schema":"gha-workload-request/v1","id":"runner-primitive-docker-u24","runner":"ubuntu-24.04",
        "timeout_minutes":8,"setup_profile":"none",
        "argv":["python3","scripts/github_runner_primitive.py","--label","ubuntu-24.04","--probe","docker-container","--out","{runner_temp}/gha-request/receipt.json"],
        "artifact_name":"runner-primitive-docker-u24","artifact_relpath":"gha-request/receipt.json",
    }

class RequestContractTests(unittest.TestCase):
    def write_request(self, value):
        td=tempfile.TemporaryDirectory(); p=pathlib.Path(td.name)/"request.json"
        p.write_text(json.dumps(value), encoding="utf-8"); return td,p
    def test_plan_is_canonical_and_stable(self):
        td,p=self.write_request(valid_request()); self.addCleanup(td.cleanup)
        a=gwr.normalized_plan(gwr.load_request(p)); b=gwr.normalized_plan(gwr.load_request(p))
        self.assertEqual(a,b); self.assertRegex(a["request_sha256"], r"^[0-9a-f]{64}$")
    def test_unknown_field_fails_closed(self):
        r=valid_request(); r["shell"]="echo nope"; td,p=self.write_request(r); self.addCleanup(td.cleanup)
        with self.assertRaises(gwr.RequestError): gwr.load_request(p)
    def test_unknown_runner_fails_closed(self):
        r=valid_request(); r["runner"]="self-hosted"; td,p=self.write_request(r); self.addCleanup(td.cleanup)
        with self.assertRaises(gwr.RequestError): gwr.load_request(p)
    def test_non_python_entrypoint_fails_closed(self):
        r=valid_request(); r["argv"]=["bash","-c","echo unsafe"]; td,p=self.write_request(r); self.addCleanup(td.cleanup)
        with self.assertRaises(gwr.RequestError): gwr.load_request(p)
    def test_script_must_stay_under_scripts(self):
        r=valid_request(); r["argv"][1]="../outside.py"; td,p=self.write_request(r); self.addCleanup(td.cleanup)
        with self.assertRaises(gwr.RequestError): gwr.load_request(p)
    def test_digest_change_blocks_execution(self):
        r=valid_request(); d=gwr.normalized_plan(r)["request_sha256"]; r["timeout_minutes"]=9
        with self.assertRaises(gwr.RequestError): gwr.execute(r,d)
    def test_execute_uses_argv_without_shell(self):
        r=valid_request(); d=gwr.normalized_plan(r)["request_sha256"]
        with tempfile.TemporaryDirectory() as td, mock.patch.dict(os.environ,{"RUNNER_TEMP":td,"GITHUB_WORKSPACE":"/workspace"},clear=False), mock.patch("subprocess.run") as run:
            run.return_value.returncode=0; rc=gwr.execute(r,d)
        self.assertEqual(rc,0); self.assertEqual(run.call_args.args[0][:2],["python3","scripts/github_runner_primitive.py"])
        self.assertFalse(run.call_args.kwargs.get("shell",False))

if __name__=="__main__":
    unittest.main()
