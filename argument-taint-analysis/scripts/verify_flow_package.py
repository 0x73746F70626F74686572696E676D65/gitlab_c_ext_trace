#!/usr/bin/env python3
"""Verify every packaged chain and checksum without executing target sources."""
import argparse, hashlib, json, tarfile
from pathlib import Path
from package_flows import NATIVE, sha, encoded


def main():
    ap=argparse.ArgumentParser();ap.add_argument('archive',type=Path);a=ap.parse_args()
    prefix='gem-api-memory-flows/';digests={};ids=set();paths=set();native=0;count=0;index=None;manifest=None;snapshot=None;checksums=None;sources=None;used_sources=set()
    with tarfile.open(a.archive,mode='r|gz') as archive:
        for member in archive:
            if member.isdir() and member.name==prefix.rstrip('/'):continue
            assert member.name.startswith(prefix) and '..' not in Path(member.name).parts,member.name
            if member.isdir():continue
            assert member.isfile(),member.name
            path=member.name[len(prefix):];assert path not in paths;paths.add(path)
            data=archive.extractfile(member).read();assert len(data)==member.size
            if path=='SHA256SUMS':checksums=data.decode();continue
            digests[path]=hashlib.sha256(data).hexdigest()
            if path.startswith('chains/'):
                row=json.loads(data);assert row['chain_id'] not in ids;ids.add(row['chain_id'])
                assert Path(path).name==row['chain_id']+'.json'
                original={k:v for k,v in row.items() if k not in {'chain_id','native_primitive','snapshot','api_entry_source','registration_source','flow'}}
                original['event_chain']=[e['id'] for e in row['flow']]
                assert hashlib.sha256(json.dumps(original,sort_keys=True,separators=(',',':')).encode()).hexdigest()==row['chain_id']
                assert row['flow'][0]['function']==row['entry_function_id']
                assert row['native_primitive']==(row['memory_kind'] in NATIVE)
                for i,e in enumerate(row['flow']):
                    assert e['step']==i and e['source']['line']==e['line']
                    assert e['line']>=1 and e['source']['source_sha256'] and e['source']['file']
                    assert 'source_line' in e['source'] and e['source']['source_url']
                    used_sources.add((e['source']['package'],e['source']['file'],e['source']['source_sha256']))
                    if e['kind']=='argument_binding':
                        assert e['binding']['formal_index']==e['formal_index'];assert e['callee_source']['line']>=1
                        s=e['callee_source'];used_sources.add((s['package'],s['file'],s['source_sha256']))
                for k in ['api_entry_source','registration_source']:
                    s=row[k];assert s['line']>=1;used_sources.add((s['package'],s['file'],s['source_sha256']))
                tail=row['flow'][-1];site=row['call_site'];assert tail['line']==site['line']
                assert tail['source']['file']==site['file'] and tail['source']['source_sha256']==site['source_sha256']
                assert row['call_depth']==sum(e['kind']=='argument_binding' for e in row['flow'])
                count+=1;native+=row['native_primitive']
                if count%10000==0:print('Verified chain files:',count,flush=True)
            elif path=='index.jsonl':index=[json.loads(line) for line in data.splitlines()]
            elif path=='manifest.json':manifest=json.loads(data)
            elif path=='snapshot.json':snapshot=json.loads(data)
            elif path=='cited-sources.json':sources=json.loads(data)
    assert manifest and snapshot and index and checksums and sources
    assert count==manifest['chain_files']==snapshot['flow_records']==len(index)
    assert native==manifest['native_primitive_chain_files']==snapshot['native_flow_records']
    assert {r['chain_id'] for r in index}==ids
    assert {r['path'] for r in index}=={p for p in paths if p.startswith('chains/')}
    expected={line.split('  ',1)[1]:line.split('  ',1)[0] for line in checksums.splitlines()};assert expected==digests
    cited={(r['package'],r['file'],r['sha256']) for r in sources};assert used_sources==cited
    assert len(cited)==manifest['source_files_cited']
    report=dict(status='passed',chain_files_verified=count,native_chain_files_verified=native,source_files_cited=len(cited),
        payload_checksums_verified=len(digests),archive_sha256=sha(a.archive),archive_bytes=a.archive.stat().st_size,
        checks=['one JSON per saved flow','exact original record identity','all event IDs and ordered steps','every source citation and line','callee/formal bindings','call-site and call-depth joins','complete API index','all payload SHA256s','snapshot counts retained'])
    a.archive.with_suffix(a.archive.suffix+'.validation.json').write_bytes(encoded(report))
    print(json.dumps(report,indent=2,sort_keys=True))


if __name__=='__main__':main()
