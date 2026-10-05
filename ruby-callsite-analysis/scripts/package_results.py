#!/usr/bin/env python3
"""Create a stable archive with individual JSONs and their shared C/provenance tables."""
import argparse,gzip,hashlib,json,tarfile
from pathlib import Path

def main():
    p=argparse.ArgumentParser();p.add_argument('--results',type=Path,required=True);p.add_argument('--archive',type=Path,required=True);a=p.parse_args()
    a.archive.parent.mkdir(parents=True,exist_ok=True)
    included=[f for f in a.results.rglob('*') if f.is_file() and f.name!='archive.json']
    with a.archive.open('wb') as raw,gzip.GzipFile(filename='',mode='wb',fileobj=raw,mtime=0,compresslevel=6) as gz,tarfile.open(fileobj=gz,mode='w') as tar:
        for path in sorted(included):
            relative='gitlab-gem-api-memory-callsites/'+path.relative_to(a.results).as_posix();info=tar.gettarinfo(str(path),arcname=relative)
            info.uid=info.gid=0;info.uname=info.gname='';info.mtime=0;info.mode=0o644
            with path.open('rb') as source:tar.addfile(info,source)
    with tarfile.open(a.archive,'r:gz') as tar:
        names=tar.getnames();individual=[n for n in names if '/callsites/' in n and n.endswith('.json')]
    summary=json.loads((a.results/'summary.json').read_text());assert len(individual)==summary['verified_callsites']
    record=dict(path=str(a.archive),bytes=a.archive.stat().st_size,sha256=hashlib.sha256(a.archive.read_bytes()).hexdigest(),individual_callsite_json_files=len(individual),total_files=len(names))
    (a.results/'archive.json').write_text(json.dumps(record,indent=2,sort_keys=True)+'\n');print(json.dumps(record,indent=2,sort_keys=True))
if __name__=='__main__':main()
