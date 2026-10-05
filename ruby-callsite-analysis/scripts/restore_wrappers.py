#!/usr/bin/env python3
"""Restore pinned Ruby gem sources without executing target gem code."""
import argparse,hashlib,io,json,tarfile,urllib.request
from pathlib import Path

def main():
    p=argparse.ArgumentParser();p.add_argument('--manifest',type=Path,required=True);p.add_argument('--destination',type=Path,required=True);p.add_argument('--packages',type=Path,required=True);a=p.parse_args()
    manifest=json.loads(a.manifest.read_text());groups={}
    for r in manifest:groups.setdefault((r['gem'],r['locked_version']),[]).append(r)
    a.packages.mkdir(parents=True,exist_ok=True)
    for (gem,version),records in sorted(groups.items()):
        first=records[0];archive=a.packages/(gem+'-'+version+'.gem')
        if not archive.exists():
            with urllib.request.urlopen(first['source_url']) as response:archive.write_bytes(response.read())
        assert hashlib.sha256(archive.read_bytes()).hexdigest()==first['package_sha256']
        with tarfile.open(archive) as outer:
            data=outer.extractfile('data.tar.gz').read()
        expected={r['file']:r for r in records}
        with tarfile.open(fileobj=io.BytesIO(data),mode='r:gz') as inner:
            for member in inner:
                r=expected.get(member.name)
                if not r:continue
                assert member.isfile();source=inner.extractfile(member).read();assert hashlib.sha256(source).hexdigest()==r['source_sha256']
                path=a.destination/(gem+'-'+version)/r['file'];assert path.resolve().is_relative_to(a.destination.resolve())
                path.parent.mkdir(parents=True,exist_ok=True);path.write_bytes(source);r['path']=str(path.resolve())
    for r in manifest:assert Path(r['path']).is_file()
    a.manifest.write_text(json.dumps(manifest,indent=2,sort_keys=True)+'\n')
    print('Restored',len(manifest),'pinned Ruby source files from',len(groups),'verified gem archives')
if __name__=='__main__':main()
