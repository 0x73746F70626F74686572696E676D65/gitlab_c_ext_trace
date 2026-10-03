#!/usr/bin/env python3
"""Reproducible end-to-end driver: restore, scavenge, trace, validate."""
import argparse, hashlib, json, os, subprocess, sys, tarfile
from pathlib import Path

def main():
    ap=argparse.ArgumentParser()
    ap.add_argument('--repo',type=Path,default=Path(__file__).resolve().parents[2])
    ap.add_argument('--cache',type=Path,required=True)
    ap.add_argument('--out',type=Path)
    ap.add_argument('--skip-scavenge',action='store_true')
    ap.add_argument('--verify-repeat',action='store_true')
    args=ap.parse_args(); out=args.out or args.repo/'argument-taint-analysis/results'
    out.mkdir(parents=True,exist_ok=True); native=args.cache/'native'; native.mkdir(parents=True,exist_ok=True)
    needed=['gems.jsonl','c_files.jsonl','c_functions.jsonl','c_registrations.jsonl','ruby_native_registrations.jsonl']
    with tarfile.open(args.repo/'gitlab-native-results.tar.gz') as archive:
        for name in needed:
            (native/name).write_bytes(archive.extractfile('results/tables/'+name).read())
    scripts=Path(__file__).resolve().parent
    def run(name,argv): subprocess.run([sys.executable,str(scripts/name),*map(str,argv)],check=True)
    with (out/'semantic-tests.log').open('w') as log:
        subprocess.run([sys.executable,str(scripts/'test_trace.py')],stdout=log,stderr=subprocess.STDOUT,check=True)
    run('recover.py',['--repo',args.repo,'--cache',args.cache,'--native-data',native,'--out',out])
    published=json.loads((out/'source-manifest.json').read_text())
    (out/'published-source-manifest.json').write_text(json.dumps(published,indent=2,sort_keys=True)+'\n')
    run('recover_git.py',['--native-data',native,'--cache',args.cache,'--out',out])
    upstream=json.loads((out/'git-source-manifest.json').read_text())
    (out/'source-manifest.json').write_text(json.dumps(published+upstream,indent=2,sort_keys=True)+'\n')
    if not args.skip_scavenge: run('scavenge.py',['--repo',args.repo,'--out',out,'--cache',args.cache/'scavenged'])
    run('verify_saved_sources.py',['--out',out,'--native-data',native])
    trace_args=['--manifest',out/'source-manifest.json','--repo',args.repo,'--native-data',native,
                '--index-cache',args.cache/'all-sources-index.json','--refresh-changed-packages']
    subprocess.run([sys.executable,str(scripts/'trace.py'),*map(str,trace_args+['--out',out,'--checkpoint',args.cache/'operand-hash1','--checkpoint-interval','300'])],check=True,env=dict(os.environ,PYTHONHASHSEED='1'))
    run('variants.py',['--repo',args.repo,'--out',out])
    run('validate.py',['--repo',args.repo,'--out',out])
    run('report.py',['--repo',args.repo,'--out',out,'--native-data',native])
    if args.verify_repeat:
        repeated=args.cache/'repeat-results'; repeated.mkdir(exist_ok=True)
        env=dict(os.environ,PYTHONHASHSEED='317')
        subprocess.run([sys.executable,str(scripts/'trace.py'),*map(str,trace_args+['--out',repeated,'--checkpoint',args.cache/'operand-hash317','--checkpoint-interval','300'])],check=True,env=env)
        names=['apis.csv','apis-primary-lock.csv','apis-by-registration.jsonl','roots.jsonl','witnesses.jsonl','events.jsonl','memory-operation-models.json','callback-table-bindings.jsonl','function-pointer-arguments.jsonl','include-boundaries.jsonl','call-abi-boundaries.jsonl']
        results={}
        for name in names:
            digest=lambda p:hashlib.sha256(p.read_bytes()).hexdigest()
            a,b=digest(out/name),digest(repeated/name); results[name]=dict(first_sha256=a,repeat_sha256=b,equal=a==b)
        (out/'repeat-validation.json').write_text(json.dumps(results,indent=2,sort_keys=True)+'\n')
        assert all(r['equal'] for r in results.values()),'repeat results differ'
        run('finalize.py',['--out',out,'--repeat',repeated,'--test-log',out/'semantic-tests.log',
                           '--index-cache',args.cache/'all-sources-index.json'])

if __name__=='__main__': main()
