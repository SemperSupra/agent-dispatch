import unittest
from unittest.mock import Mock, call, patch
import discover
from discover import classify, Hold
from discover import enumerate_candidates

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
    def test_malformed_repository_is_hold(self):
        for value in (None, [], "bad", 7):
            with self.subTest(value=value):
                self.deny(payload(run(repository=value)),"INVALID_RUN_REPOSITORY")
    def test_boolean_workflow_id_is_not_integer(self):
        self.deny(payload(run(workflow_id=True)),"INVALID_WORKFLOW_ID")
    def test_invalid_oracle_is_hold(self):
        for value in (True, "101", 0, None):
            with self.subTest(value=value), self.assertRaisesRegex(Hold,"INVALID_DISCOVERY_SCOPE"):
                classify(payload(run()),REPO,WORKFLOW,HEAD,value)

class BoundedVisibility(unittest.TestCase):
    def test_malformed_self_read_is_hold_before_listing(self):
        env={"GITHUB_ACTIONS":"true","GITHUB_EVENT_NAME":"pull_request",
             "GITHUB_REPOSITORY":REPO,"GITHUB_TOKEN":"synthetic-test-only",
             "SOURCE_HEAD_SHA":HEAD,"GITHUB_RUN_ID":"101"}
        for value in (None, [], "bad"):
            with self.subTest(value=value), patch.dict(discover.os.environ,env,clear=True), \
                 patch.object(discover,"get_json",return_value=value) as read:
                with self.assertRaisesRegex(Hold,"SELF_NATIVE_RUN_MISMATCH"):
                    discover.main()
                read.assert_called_once()
    def observe(self, read, sleep):
        return enumerate_candidates(read,sleep,REPO,WORKFLOW,HEAD,101)
    def test_delayed_visibility_reads_only_and_keeps_query(self):
        read=Mock(side_effect=[payload(),payload(run(104)),payload(run())])
        sleep=Mock()
        self.assertEqual(self.observe(read,sleep)["classification"],"ONE_CANDIDATE_AT_READBACK")
        self.assertEqual(sleep.call_args_list,[call(2),call(2)])
        self.assertEqual(read.call_count,3)
        paths=[args.args[0] for args in read.call_args_list]
        self.assertEqual(len(set(paths)),1)
        self.assertNotIn("101",paths[0])
        self.assertIn("head_sha="+HEAD,paths[0])
    def test_missing_run_exhausts_without_final_sleep(self):
        read=Mock(return_value=payload())
        sleep=Mock()
        with self.assertRaisesRegex(Hold,"CURRENT_RUN_ABSENT"):
            self.observe(read,sleep)
        self.assertEqual(read.call_count,5)
        self.assertEqual(sleep.call_args_list,[call(2)]*4)
    def test_incomplete_listing_is_not_retried(self):
        read=Mock(return_value={"total_count":2,"workflow_runs":[run()]})
        sleep=Mock()
        with self.assertRaisesRegex(Hold,"INCONSISTENT"):self.observe(read,sleep)
        read.assert_called_once()
        sleep.assert_not_called()
    def test_multiple_runs_hold_without_waiting_for_uniqueness(self):
        read=Mock(return_value=payload(run(),run(102)))
        sleep=Mock()
        self.assertEqual(self.observe(read,sleep)["classification"],"AMBIGUOUS_MULTIPLE_CANDIDATES_HOLD")
        read.assert_called_once()
        sleep.assert_not_called()
    def test_provider_failure_is_not_retried(self):
        read=Mock(side_effect=Hold("PROVIDER_HTTP_403"))
        sleep=Mock()
        with self.assertRaisesRegex(Hold,"PROVIDER_HTTP_403"):self.observe(read,sleep)
        read.assert_called_once()
        sleep.assert_not_called()
if __name__=="__main__":unittest.main()
