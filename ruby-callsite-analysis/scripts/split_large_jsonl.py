#!/usr/bin/env python3
"""Keep versioned JSONL files under 32 MiB without splitting records."""
import argparse,hashlib,json
from pathlib import Path

def main():
    ap=argparse.ArgumentParser();ap.add_argument('--out',type=Path,required=True);a=ap.parse_args();limit=32*1024*1024;changed=[]
    for path in sorted(a.out.glob('*.jsonl')):
        if path.stat().st_size<=limit:continue
        directory=a.out/(path.stem+'-jsonl');directory.mkdir(exist_ok=True);part=0;written=0;out=None;parts=[]
        try:
            with path.open('rb') as source:
                for row in source:
                    assert len(row)<=limit,(path,'one record exceeds part size')
                    if out is None or written+len(row)>limit:
                        if out:out.close()
                        part+=1;p=directory/f'part-{part:04d}.jsonl';out=p.open('wb');written=0;parts.append(p)
                    out.write(row);written+=len(row)
        finally:
            if out:out.close()
        record=dict(original_file=path.name,original_bytes=path.stat().st_size,original_sha256=hashlib.sha256(path.read_bytes()).hexdigest(),parts=[dict(path=p.relative_to(a.out).as_posix(),bytes=p.stat().st_size,sha256=hashlib.sha256(p.read_bytes()).hexdigest()) for p in parts]);changed.append(record);path.unlink()
    (a.out/'jsonl-parts.json').write_text(json.dumps(changed,indent=2,sort_keys=True)+'\n');print(json.dumps(changed,indent=2,sort_keys=True))
if __name__=='__main__':main()
