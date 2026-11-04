"""Hermetic parser falsification; this never collects Docker or TrueNAS state."""
import copy
import unittest

from truenas_takeout_terminal_diagnostic import verify, Blocked

IMG = 'sha256:' + 'c' * 64
APP = {'name': 'rdte-takeout', 'state': 'STOPPED'}
INSPECT = [{
    'Id': 'a' * 64, 'Image': IMG,
    'Config': {'User': '10001:10001', 'ExposedPorts': None,
               'Labels': {'com.docker.compose.project': 'ix-rdte-takeout',
                          'com.docker.compose.service': 'takeoutsynthetic',
                          'com.docker.compose.container-number': '1'}},
    'HostConfig': {'ReadonlyRootfs': True, 'Privileged': False,
                   'CapDrop': ['ALL'], 'SecurityOpt': ['no-new-privileges:true'],
                   'PortBindings': {}, 'PublishAllPorts': False},
    'Mounts': [{'Type': 'bind', 'Source': '/mnt/rdtepool/takeout/archive',
                'Destination': '/archive', 'RW': True},
               {'Type': 'bind', 'Source': '/mnt/rdtepool/takeout/state',
                'Destination': '/state', 'RW': True}],
    'State': {'Status': 'exited', 'Running': False, 'Dead': False,
              'OOMKilled': False, 'Error': '', 'ExitCode': 0,
              'StartedAt': '2026-10-14T15:10:01.123456789Z',
              'FinishedAt': '2026-10-14T15:10:05.123456789Z'}
}]
KW = {'app_name': 'rdte-takeout', 'project': 'ix-rdte-takeout',
      'service': 'takeoutsynthetic', 'config_sha': IMG,
      'archive_host': '/mnt/rdtepool/takeout/archive',
      'state_host': '/mnt/rdtepool/takeout/state',
      'not_before': '2026-10-14T15:10:00Z'}


class DiagnosticTests(unittest.TestCase):
    def good(self):
        return copy.deepcopy(APP), copy.deepcopy(INSPECT), KW.copy()

    def test_positive_but_diagnostic_only(self):
        a, i, kw = self.good()
        result = verify(a, i, **kw)
        self.assertEqual(result['status'], 'PROCESS_EXIT_ZERO_OBSERVED')
        self.assertFalse(result['foundry_ensure_completed_qualified'])

    def test_native_app_state_cannot_be_overruled(self):
        for state in ('RUNNING', 'CRASHED', None):
            with self.subTest(state=state):
                a, i, kw = self.good(); a['state'] = state
                with self.assertRaises(Blocked): verify(a, i, **kw)

    def test_duplicate_or_missing_inspect(self):
        for mult in (0, 2):
            a, i, kw = self.good(); i *= mult
            with self.assertRaises(Blocked): verify(a, i, **kw)

    def test_nonzero_bool_missing_exit(self):
        for code in (1, False, None):
            a, i, kw = self.good(); i[0]['State']['ExitCode'] = code
            with self.assertRaises(Blocked): verify(a, i, **kw)

    def test_status_or_oom_or_running(self):
        for name, value in [('Status','running'), ('OOMKilled',True), ('Running',True),('Error','error')]:
            a, i, kw = self.good(); i[0]['State'][name] = value
            with self.assertRaises(Blocked): verify(a, i, **kw)

    def test_wrong_digest_or_ownership(self):
        for key in ('Image',):
            a, i, kw = self.good(); i[0][key] = 'sha256:' + 'd' * 64
            with self.assertRaises(Blocked): verify(a, i, **kw)
        for label in ('com.docker.compose.project','com.docker.compose.service','com.docker.compose.container-number'):
            a, i, kw = self.good(); i[0]['Config']['Labels'][label] = 'wrong'
            with self.assertRaises(Blocked): verify(a, i, **kw)

    def test_no_privilege_or_public_ingress(self):
        for name, value in [('ReadonlyRootfs',False), ('Privileged',True),
                            ('CapDrop',[]), ('SecurityOpt',[]),
                            ('PortBindings',{'80/tcp':[]})]:
            a,i,kw=self.good(); i[0]['HostConfig'][name]=value
            with self.assertRaises(Blocked): verify(a,i,**kw)
        a,i,kw=self.good(); i[0]['Config']['ExposedPorts']={'80/tcp':{}}
        with self.assertRaises(Blocked): verify(a,i,**kw)

    def test_exact_private_host_mounts(self):
        for patch in [('Source','/var/run/docker.sock'),('RW',False),('Destination','/other')]:
            a,i,kw=self.good();i[0]['Mounts'][0][patch[0]]=patch[1]
            with self.assertRaises(Blocked):verify(a,i,**kw)

    def test_allow_bounded_tmpfs_with_two_exact_bind_mounts(self):
        a,i,kw=self.good()
        i[0]['Mounts'].append({'Type':'tmpfs','Destination':'/tmp','RW':True,
                                'Source':''})
        self.assertEqual(verify(a,i,**kw)['status'],'PROCESS_EXIT_ZERO_OBSERVED')

    def test_reject_foreign_tmpfs_or_third_bind(self):
        for path in ('/run', '/state'):
            a,i,kw=self.good()
            i[0]['Mounts'].append({'Type':'tmpfs','Destination':path,'RW':True})
            with self.assertRaises(Blocked):verify(a,i,**kw)
        a,i,kw=self.good()
        i[0]['Mounts'].append({'Type':'bind','Source':'/mnt/rdtepool/foreign',
                                'Destination':'/private','RW':True})
        with self.assertRaises(Blocked):verify(a,i,**kw)

    def test_old_or_incoherent_exit_timestamps(self):
        for field,value in [('StartedAt','2026-10-14T15:09:59Z'),
                            ('FinishedAt','2026-10-14T15:09:59Z'),
                            ('FinishedAt','0001-01-01T00:00:00Z'),
                            ('StartedAt','garbage')]:
            a,i,kw=self.good();i[0]['State'][field]=value
            with self.assertRaises(Blocked):verify(a,i,**kw)


if __name__=='__main__':
    unittest.main()
