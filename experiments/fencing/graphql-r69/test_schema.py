import copy
import unittest
from graphql_probe import Hold, validate

def fld(name, kind="SCALAR", t="GitObjectID"):
    return {"name":name,"type":{"kind":kind,"name":t if kind=="SCALAR" else None,"ofType":{"name":t}}}

def fixture():
    return {"data":{
      "ref":{"name":"RefUpdate","kind":"INPUT_OBJECT","inputFields":[
        fld("name","NON_NULL","GitRefname"),fld("afterOid","NON_NULL"),
        fld("beforeOid"),fld("force","SCALAR","Boolean")]},
      "input":{"name":"UpdateRefsInput","kind":"INPUT_OBJECT","inputFields":[
        fld("repositoryId","NON_NULL","ID"),fld("refUpdates","NON_NULL","RefUpdate")]},
      "mutation":{"fields":[{"name":"updateRefs"},{"name":"other"}]}
    }}

class Tests(unittest.TestCase):
    def test_expected_schema_not_mutation(self):
        self.assertEqual(validate(fixture())["real_cas_contention"], "NOT_TESTED")
    def bad(self, fn, code):
        d=fixture()
        fn(d)
        with self.assertRaisesRegex(Hold,code): validate(d)
    def test_before_oid_missing(self):
        self.bad(lambda d:d["data"]["ref"]["inputFields"].pop(2),"REF_COMPARE")
    def test_wrong_type(self):
        self.bad(lambda d:d["data"]["ref"]["inputFields"][2]["type"].update(name="String"),"BEFORE_OID")
    def test_no_mutation(self):
        self.bad(lambda d:d["data"]["mutation"].update(fields=[]),"UPDATE_REFS")
    def test_no_repository(self):
        self.bad(lambda d:d["data"]["input"]["inputFields"].pop(0),"ATOMIC_BATCH")
    def test_provider_errors(self):
        self.bad(lambda d:d.update(errors=[{"message":"Denied"}]),"GRAPHQL_ERRORS")
    def test_missing_ref(self):
        self.bad(lambda d:d["data"].update(ref=None),"EXPECTED_INPUT")
    def test_duplicate_field(self):
        self.bad(lambda d:d["data"]["ref"]["inputFields"].append(fld("beforeOid")),"REF_COMPARE")
    def test_required_after_oid(self):
        self.bad(lambda d:d["data"]["ref"]["inputFields"][1]["type"].update(kind="SCALAR"),"REF_TARGET")
if __name__=="__main__": unittest.main()
