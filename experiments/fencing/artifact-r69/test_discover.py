import unittest
from discover import classify, Hold

REPO="SemperSupra/agent-dispatch"
HEAD="a"*40
WORKFLOW=45
def run(rid=101,**overrides):
    v={"id":rid,"workflow_id":WORKFLOW,"head_sha":HEAD,"event":"pull_request",
       "repository":{"full_name":REPO}}
    v.update(overrides)
    return v
def payload(*runs):
    return {"total_count":len(runs),"workflow_runs":list(runs)}

class DiscoveryNegatives(unittest.TestCase):
    def test_unique_candidate(self):
        x=classify(payload(run()),REPO,WORKFLOW,HEAD,101)
        self.assertEqual(x["classification"],"ONE_CANDIDATE_AT_READBACK")
        self.assertFalse(x["list_query_used_run_id"])
    def test_ambiguity_is_not_unique(self):
        x=classify(payload(run(),run(102)),REPO,WORKFLOW,HEAD,101)
        self.assertEqual(x["classification"],"AMBIGUOUS_MULTIPLE_CANDIDATES_HOLD")
    def deny(self,x,expected):
        with self.assertRaisesRegex(Hold,expected):
            classify(x,REPO,WORKFLOW,HEAD,101)
    def test_no_native_run_in_list(self):self.deny(payload(run(104)),"ABSENT")
    def test_cross_repository(self):
        self.deny(payload(run(repository={"full_name":"public-other/repo"})),"CROSS_SCOPE")
    def test_wrong_workflow(self):self.deny(payload(run(workflow_id=89)),"CROSS_SCOPE")
    def test_wrong_head(self):self.deny(payload(run(head_sha="b"*40)),"CROSS_SCOPE")
    def test_duplicate_identifiers(self):self.deny(payload(run(),run()),"DUPLICATE")
    def test_truncation(self):self.deny({"total_count":2,"workflow_runs":[run()]},"INCONSISTENT")
    def test_pagination_over_100(self):self.deny({"total_count":101,"workflow_runs":[]},"PAGINATION")
    def test_wrong_event(self):self.deny(payload(run(event="workflow_dispatch")),"CROSS_SCOPE")
if __name__=="__main__":unittest.main()
