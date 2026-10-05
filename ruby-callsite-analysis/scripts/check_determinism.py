#!/usr/bin/env python3
"""Replay the semantic fixture suite under distinct Python hash seeds."""
import argparse,hashlib,json,os,subprocess,sys
from pathlib import Path

def main():
    ap=argparse.ArgumentParser();ap.add_argument('--out',type=Path,required=True);a=ap.parse_args()
    # Every fixture invokes run(); capture the complete engine evidence and results.
    script=r'''
import contextlib,hashlib,io,json,unittest
import test_analysis as fixtures
snapshots=[]
original=fixtures.run
def capture(*args,**kwargs):
 e,sites=original(*args,**kwargs)
 snapshots.append(dict(events=e.events,calls=e.calls,accepted=sites))
 return e,sites
fixtures.run=capture
with contextlib.redirect_stdout(io.StringIO()):
 result=unittest.TextTestRunner(stream=io.StringIO()).run(unittest.defaultTestLoader.loadTestsFromModule(fixtures))
assert result.wasSuccessful()
print(json.dumps(dict(tests=result.testsRun,captures=len(snapshots),sha256=hashlib.sha256(json.dumps(snapshots,sort_keys=True,separators=(',',':')).encode()).hexdigest()),sort_keys=True))
'''
    results=[]
    for seed in ('1','918273'):
        env=dict(os.environ,PYTHONHASHSEED=seed);raw=subprocess.check_output([sys.executable,'-c',script],cwd=Path(__file__).parent,env=env,text=True);results.append(dict(hash_seed=seed,**json.loads(raw)))
    assert results[0]['sha256']==results[1]['sha256']
    report=dict(passed=True,scope='Full semantic fixture suite evidence and accepted records replayed; repository fixed point is run once',results=results)
    a.out.write_text(json.dumps(report,indent=2,sort_keys=True)+'\n');print(json.dumps(report,indent=2,sort_keys=True))
if __name__=='__main__':main()
