"""Azurite offline negative controls: no real cloud, paid resource, or forged ETag pass."""
import importlib.util
import hashlib
import json
from pathlib import Path
import sys
import unittest

ROOT=Path(__file__).resolve().parents[1]
P=ROOT/"scripts"/"verify_azurite_transport.py"
spec=importlib.util.spec_from_file_location("verify_azurite_transport",P)
m=importlib.util.module_from_spec(spec)
sys.modules[spec.name]=m
spec.loader.exec_module(m)
SHA="a"*40
RUN="12345678"
ETAG='"synthetic-r1"'
NEXT='"synthetic-r2"'

def fixture():
    a={
      "schema":"azurite-transport-phase/v1","phase":"write",
      "etag":ETAG,"sha256":hashlib.sha256(b"public-synthetic-artifact-v1\n").hexdigest(),
      "length":len(b"public-synthetic-artifact-v1\n"),
      "create_status":201,"replay_status":412,"provider_access_verified":False,
    }
    b={
      "schema":"azurite-transport-phase/v1","phase":"recover",
      "old_etag":ETAG,"etag":NEXT,
      "sha256":hashlib.sha256(b"public-synthetic-artifact-v2\n").hexdigest(),
      "length":len(b"public-synthetic-artifact-v2\n"),
      "stale_write_status":412,"conditional_update_status":201,
      "stale_read_status":412,"recovered_from_new_process":True,
      "provider_access_verified":False,
    }
    return a,b

def encoded(a,b):
    return json.dumps(a).encode(),json.dumps(b).encode()


class EmulatorNegativeTests(unittest.TestCase):
    def test_synthetic_oracle_positive_is_not_live(self):
        a,b=fixture()
        verdict=m.verify(*encoded(a,b),SHA,RUN)
        self.assertEqual(verdict["classification"],"EMULATOR_ONLY_PASS")
        self.assertFalse(verdict["provider_access_verified"])
        self.assertEqual(verdict["max_cost_usd"],0)
        self.assertTrue(verdict["fresh_client_recovered"])
        self.assertIn("@sha256:",verdict["immutable_image"])

    def test_all_revision_and_replay_mutations_denied(self):
        mutations=[("a","replay_status",201),("a","create_status",200),
                   ("b","stale_write_status",200),("b","stale_read_status",200),
                   ("b","conditional_update_status",412),("b","old_etag",NEXT),
                   ("b","etag",ETAG),("b","recovered_from_new_process",False),
                   ("a","provider_access_verified",True),
                   ("b","provider_access_verified",True)]
        for phase,field,val in mutations:
            with self.subTest(field=field):
                a,b=fixture()
                (a if phase=="a" else b)[field]=val
                with self.assertRaises(m.Denied):
                    m.verify(*encoded(a,b),SHA,RUN)

    def test_digest_and_source_drifts_denied(self):
        a,b=fixture()
        for phase in ("a","b"):
            x,y=fixture()
            (x if phase=="a" else y)["sha256"]="0"*64
            with self.assertRaisesRegex(m.Denied,"PAYLOAD_DIGEST_DENIED"):
                m.verify(*encoded(x,y),SHA,RUN)
        with self.assertRaisesRegex(m.Denied,"SOURCE_INVALID"):
            m.verify(*encoded(a,b),"","1")

    def test_extra_fields_duplicate_json_bool_and_private_data_denied(self):
        a,b=fixture()
        for k,v in (("token","fake"),("private_account","no"),("cloud_url","url")):
            x,y=fixture()
            x[k]=v
            with self.assertRaisesRegex(m.Denied,"WRITE_FIELDS_DENIED"):
                m.verify(*encoded(x,y),SHA,RUN)
        raw=encoded(a,b)[0].replace(b'"phase":',b'"phase":"write", "phase":')
        with self.assertRaisesRegex(m.Denied,"DUPLICATE_FIELD"):
            m.verify(raw,encoded(a,b)[1],SHA,RUN)
        a["replay_status"]=True
        with self.assertRaises(m.Denied):
            m.verify(*encoded(a,b),SHA,RUN)

    def test_error_shape_and_source_are_bounded(self):
        src=(ROOT/"scripts"/"azurite_blob_etag.js").read_text()
        shell=(ROOT/"scripts"/"qualify_azurite_transport.sh").read_text()
        self.assertIn('http://127.0.0.1:10000/devstoreaccount1',src)
        self.assertIn("--internal",shell)
        self.assertIn("--read-only",shell)
        self.assertNotIn(" -p 10000:10000",shell)
        self.assertNotIn("docker logs",shell)
        self.assertNotIn("login.microsoftonline.com",src)
        self.assertNotIn("graph.microsoft.com",src)
        self.assertNotIn("https://",src)
        self.assertNotIn("shell=True",src)
        self.assertIn("mcr.microsoft.com/azure-storage/azurite@sha256:",shell)


if __name__=="__main__":
    unittest.main()
