import unittest
from scripts.external_wake_receipt import validate

GOOD={"timer_id":"sample-timer-001","revision":"0123456789abcdef","generation":1,"scheduled_for":"2026-10-11T20:30:00.000Z","occurrence_id":"sample-timer-001:1:2026-10-11T20:30:00.000Z"}
class TestReceipt(unittest.TestCase):
    def test_positive(self):
        assert validate(GOOD)["status"]=="WAKE_EVENT_RECEIVED_NOT_WORK_ACCEPTED"
    def test_negatives(self):
        for mutation in ({"timer_id":"../../private"},{"revision":"private/SemperSupra"},{"generation":False}, {"scheduled_for":"yesterday"}, {"occurrence_id":"bad"}, {"private_path":"top-secret"}):
            with self.subTest(mutation=mutation),self.assertRaises(ValueError):
                validate({**GOOD,**mutation})
    def test_empty(self):
        with self.assertRaises(ValueError):validate({})
