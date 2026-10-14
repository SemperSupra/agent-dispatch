"""Falsification of native docker.events payload mapping; no TrueNAS connection."""
import copy
import unittest
from truenas_takeout_docker_event_oracle import Blocked, event_witness

CID='b'*64
PROJECT='ix-rdte-takeout'
APP={'name':'rdte-takeout','state':'STOPPED'}
SUB={'stream':'docker.events','permission':'DOCKER_READ',
     'ready_before_apply':True,'disconnect_count':0,
     'opened_ns':1_760_461_800_000_000_000,
     'closed_ns':1_760_461_820_000_000_000}
KW={'app_name':'rdte-takeout','project':PROJECT,
    'service':'takeoutsynthetic','expected_container_id':CID,
    'not_before_ns':1_760_461_801_000_000_000}

def e(action,ts,id=CID,service='takeoutsynthetic'):
    attrs={'com.docker.compose.project':PROJECT,
           'com.docker.compose.service':service,
           'com.docker.compose.container-number':'1',
           'image':'takeout-synthetic:local'}
    if action=='die':attrs['exitCode']='0'
    return {'id':PROJECT,'fields':{'Type':'container','Action':action,
                                   'Actor':{'ID':id,'Attributes':attrs},
                                   'timeNano':ts}}

EVENTS=[e('create',1_760_461_802_000_000_000),
        e('start',1_760_461_803_000_000_000),
        e('die',1_760_461_804_000_000_000)]

class NativeEventTests(unittest.TestCase):
    def fixture(self):
        return copy.deepcopy(EVENTS),copy.deepcopy(APP),copy.deepcopy(SUB),KW.copy()
    def test_success_is_only_event_shape(self):
        a,b,c,d=self.fixture(); v=event_witness(a,b,c,**d)
        self.assertEqual(v['status'],'EVENT_SEQUENCE_EXIT_ZERO_OBSERVED')
        self.assertFalse(v['subscription_provenance_verified'])
        self.assertFalse(v['foundry_ensure_completed_qualified'])
    def test_missing_event_blocks(self):
        for i in range(3):
            a,b,c,d=self.fixture();a.pop(i)
            with self.assertRaises(Blocked): event_witness(a,b,c,**d)
    def test_duplicate_die_blocks(self):
        a,b,c,d=self.fixture();a.append(copy.deepcopy(a[-1]))
        with self.assertRaises(Blocked): event_witness(a,b,c,**d)
    def test_nonzero_and_missing_exit(self):
        for code in ('1',None,0,False):
            a,b,c,d=self.fixture();a[-1]['fields']['Actor']['Attributes']['exitCode']=code
            with self.assertRaises(Blocked):event_witness(a,b,c,**d)
    def test_wrong_actor_or_project_or_replica(self):
        for field in ('ID','project','replica'):
            a,b,c,d=self.fixture()
            if field=='ID':a[-1]['fields']['Actor']['ID']='c'*64
            elif field=='project':a[-1]['fields']['Actor']['Attributes']['com.docker.compose.project']='ix-foreign'
            else:a[-1]['fields']['Actor']['Attributes']['com.docker.compose.container-number']='2'
            with self.assertRaises(Blocked):event_witness(a,b,c,**d)
    def test_disconnected_not_accepted(self):
        for k,v in [('ready_before_apply',False),('disconnect_count',1),('permission','APPS_READ'),('stream','app.query')]:
            a,b,c,d=self.fixture();c[k]=v
            with self.assertRaises(Blocked):event_witness(a,b,c,**d)
    def test_crashed_app_state_blocks(self):
        a,b,c,d=self.fixture();b['state']='CRASHED'
        with self.assertRaises(Blocked):event_witness(a,b,c,**d)
    def test_incoherent_or_stale_order(self):
        for val in (1_760_461_800_500_000_000,1_760_461_804_000_000_000,True,None):
            a,b,c,d=self.fixture();a[0]['fields']['timeNano']=val
            with self.assertRaises(Blocked):event_witness(a,b,c,**d)
    def test_fatal_oom_or_kill_or_restart(self):
        for action in ('oom','kill','restart','destroy'):
            a,b,c,d=self.fixture();a.append(e(action,1_760_461_804_500_000_000))
            with self.assertRaises(Blocked):event_witness(a,b,c,**d)
    def test_reject_second_worker(self):
        a,b,c,d=self.fixture();a.append(e('create',1_760_461_801_800_000_000,id='c'*64))
        with self.assertRaises(Blocked):event_witness(a,b,c,**d)
    def test_ignore_other_service_and_foreign_project(self):
        a,b,c,d=self.fixture();a.insert(0,e('die',1_760_461_801_800_000_000,service='permissions'))
        a.append({'id':'ix-other','fields':{'Type':'container','Action':'die'}})
        self.assertEqual(event_witness(a,b,c,**d)['status'],'EVENT_SEQUENCE_EXIT_ZERO_OBSERVED')
    def test_missing_timenano_or_double_subscription(self):
        a,b,c,d=self.fixture();del a[-1]['fields']['timeNano']
        with self.assertRaises(Blocked):event_witness(a,b,c,**d)
        a,b,c,d=self.fixture();c['opened_ns']=c['closed_ns']+1
        with self.assertRaises(Blocked):event_witness(a,b,c,**d)

if __name__=='__main__':unittest.main()
