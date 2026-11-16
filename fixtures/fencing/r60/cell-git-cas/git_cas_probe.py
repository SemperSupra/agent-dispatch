"""Disposable native Git compare-and-swap test driver, NOT remote GitHub acceptance."""
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from tempfile import TemporaryDirectory
from threading import Barrier
import os, subprocess, json

def g(path,*args,input=None,check=True):
    r=subprocess.run(['git','--git-dir',str(path),*args], input=input, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False, env={**os.environ,'GIT_AUTHOR_NAME':'test','GIT_AUTHOR_EMAIL':'test@invalid.example','GIT_COMMITTER_NAME':'test','GIT_COMMITTER_EMAIL':'test@invalid.example'})
    if check and r.returncode: raise RuntimeError(f"git {' '.join(args)}: {r.stderr}")
    return r

def race(repo,ref,base,candidates,creation=False):
    gate=Barrier(2)
    def try_update(candidate):
        gate.wait(timeout=8)
        return (candidate,g(repo,'update-ref',ref,candidate,'0'*40 if creation else base,check=False).returncode)
    with ThreadPoolExecutor(max_workers=2) as pool:
        futures=[pool.submit(try_update,x) for x in candidates]
        results=[x.result(timeout=8) for x in futures]
    winners=[h for h,code in results if code==0]
    assert len(winners)==1,results
    assert g(repo,'rev-parse',ref).stdout.strip()==winners[0]
    return winners[0]

def main():
    with TemporaryDirectory(prefix='ad-r60-git-native-') as td:
        repo=Path(td)/'authority.git'; repo.mkdir()
        subprocess.run(['git','init','--bare','-q',str(repo)],check=True)
        empty=g(repo,'hash-object','-t','tree','-w','--stdin',input='').stdout.strip()
        first=g(repo,'commit-tree',empty,input='root').stdout.strip()
        child_a=g(repo,'commit-tree',empty,'-p',first,input='actor-A').stdout.strip()
        child_b=g(repo,'commit-tree',empty,'-p',first,input='actor-B').stdout.strip()
        assert len({first,child_a,child_b})==3
        create_trials=150; update_trials=150
        for i in range(create_trials):
            race(repo,f'refs/heads/synthetic-create-{i}',first,(child_a,child_b),creation=True)
        for i in range(update_trials):
            ref=f'refs/heads/synthetic-update-{i}'
            g(repo,'update-ref',ref,first,'0'*40)
            race(repo,ref,first,(child_a,child_b))
        # EXPECTED RED: unrestricted ref reset allows stale old OID reuse (ABA).
        ref='refs/heads/synthetic-aba'
        g(repo,'update-ref',ref,first,'0'*40)
        g(repo,'update-ref',ref,child_a,first)
        g(repo,'update-ref',ref,first,child_a)
        aba=g(repo,'update-ref',ref,child_b,first,check=False)
        assert aba.returncode==0
        ref='refs/heads/synthetic-lost-ack'
        g(repo,'update-ref',ref,first,'0'*40)
        g(repo,'update-ref',ref,child_a,first)
        retry=g(repo,'update-ref',ref,child_a,first,check=False)
        assert retry.returncode!=0 and g(repo,'rev-parse',ref).stdout.strip()==child_a
        print(json.dumps({'venue':'disposable_local_native_git','create_trials':create_trials,'update_trials':update_trials,'atomic_ref_winners':create_trials+update_trials,'lost_ack_retry':'DENIED_AND_READBACK_RECOVERS_COMMIT','unrestricted_reset_aba':'EXPECTED_RED','cloud_git_graphql':'NOT_TESTED','at_sink_fencing':'NOT_TESTED','private_github_actions_minutes':0,'pass':True},sort_keys=True))
if __name__=='__main__':main()
