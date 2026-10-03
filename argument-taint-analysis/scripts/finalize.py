#!/usr/bin/env python3
"""Freeze replay comparisons and delivery digests after all checks pass."""
import argparse,hashlib,json,re
from pathlib import Path

def main():
    ap=argparse.ArgumentParser();ap.add_argument('--out',type=Path,required=True)
    ap.add_argument('--repeat',type=Path,required=True);ap.add_argument('--test-log',type=Path,required=True)
    ap.add_argument('--index-cache',type=Path,required=True)
    a=ap.parse_args()
    def digest(path):
        h=hashlib.sha256()
        with path.open('rb') as f:
            for block in iter(lambda:f.read(4*1024*1024),b''):h.update(block)
        return h.hexdigest()
    names=['apis.csv','apis-primary-lock.csv','apis-by-registration.jsonl','roots.jsonl','witnesses.jsonl','events.jsonl','memory-operation-models.json','callback-table-bindings.jsonl','function-pointer-arguments.jsonl','include-boundaries.jsonl','call-abi-boundaries.jsonl']
    pairs={}
    for name in names:
        first,repeat=digest(a.out/name),digest(a.repeat/name)
        pairs[name]=dict(first_sha256=first,repeat_sha256=repeat,equal=first==repeat)
    (a.out/'repeat-validation.json').write_text(json.dumps(pairs,indent=2,sort_keys=True)+'\n')
    assert all(v['equal'] for v in pairs.values()),'deterministic replay differs'
    log=a.test_log.read_text();assert '\nOK\n' in log
    scripts=Path(__file__).resolve().parent
    report=dict(status='passed',semantic_tests=int(re.search(r'Ran (\d+) tests',log)[1]),semantic_test_log_sha256=digest(a.test_log),index_cache_sha256=digest(a.index_cache),
        scripts={p.name:digest(p) for p in sorted(scripts.glob('*.py'))},parser_requirements_sha256=digest(scripts/'requirements.txt'),
        replay_hash_seeds=[1,317])
    (a.out/'harness-validation.json').write_text(json.dumps(report,indent=2,sort_keys=True)+'\n')
    root=a.out.parent;files=sorted(p for p in root.rglob('*') if p.is_file() and '__pycache__' not in p.parts and p.name!='SHA256SUMS')
    (root/'SHA256SUMS').write_text(''.join(digest(p)+'  '+str(p.relative_to(root))+'\n' for p in files))
    print('Replay identical:',len(pairs),'outputs; delivery digests:',len(files))

if __name__=='__main__':main()
