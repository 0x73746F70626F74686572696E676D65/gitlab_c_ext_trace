#!/usr/bin/env python3
"""Package saved flows as self-contained, source-cited JSON chain files."""
import argparse, collections, gzip, hashlib, io, json, re, tarfile
from pathlib import Path
from urllib.parse import quote

NATIVE={'allocation','copy','memory_set','memory_read','release','format_buffer'}


def sha(path):
    h=hashlib.sha256()
    with path.open('rb') as stream:
        for block in iter(lambda:stream.read(4*1024*1024),b''):h.update(block)
    return h.hexdigest()


def encoded(value):return (json.dumps(value,indent=2,sort_keys=True,ensure_ascii=True)+'\n').encode()


def main():
    ap=argparse.ArgumentParser();ap.add_argument('--results',type=Path,required=True);ap.add_argument('--archive',type=Path,required=True)
    a=ap.parse_args();base=a.results;layout=json.loads((base/'gem-api-memory-flow-files.json').read_text())
    snapshot=json.loads((base/'gem-api-memory-flow-snapshot.json').read_text())
    packages={}
    for p in json.loads((base/'source-manifest.json').read_text()):
        key=p['gem']+'@'+p['locked_version']+(':'+p['source_variant'] if p.get('source_variant') else '')
        packages[key]=p
    prefixes=sorted(packages,key=len,reverse=True);file_maps={k:{r['file']:r for r in p['source_files']} for k,p in packages.items()}
    source_lines={};used_sources=set();function_cache={}
    def function_source(fid):
        if fid not in function_cache:
            package=next(k for k in prefixes if fid.startswith(k+':'))
            match=re.fullmatch(r'(.*):(\d+):(.*)',fid[len(package)+1:]);assert match,fid
            file,line,name=match.groups()
            function_cache[fid]=dict(package=package,file=file,line=int(line),function=name)
        return function_cache[fid]
    def citation(package,file,line,function=None,expected_sha=None):
        p=packages[package];r=file_maps[package][file];key=(package,file)
        if expected_sha:assert expected_sha==r['sha256'],key
        if key not in source_lines:
            raw=(Path(p['directory'])/file).read_bytes();assert hashlib.sha256(raw).hexdigest()==r['sha256'],key
            source_lines[key]=raw.decode('utf-8','replace').splitlines()
        assert 1<=line<=len(source_lines[key]),(key,line)
        used_sources.add(key)
        c=dict(package=package,gem=p['gem'],version=p['version'],file=file,line=line,function=function,
            source_sha256=r['sha256'],source_line=source_lines[key][line-1],source_url=p['source_url'],
            source_variant=p.get('source_variant','published'),package_sha256=p.get('package_sha256'))
        if r.get('git_commit'):
            url=r['git_url'].removesuffix('.git');relative=file
            boundaries=[v for v in p.get('gitlinks',[])+p.get('vendored_sources',[]) if v.get('url',v.get('git_url'))==r['git_url'] and file.startswith(v.get('path','')+'/')]
            if boundaries:
                prefix=max((v['path'] for v in boundaries),key=len);relative=file[len(prefix)+1:]
            c.update(git_url=r['git_url'],git_commit=r['git_commit'],git_blob=r.get('git_blob'),repository_file=relative)
            if url.startswith('https://github.com/'):
                c['permalink']=url+'/blob/'+r['git_commit']+'/'+quote(relative,safe='/')+'#L'+str(line)
        return c
    events={}
    with (base/'gem-api-memory-flow-events.jsonl').open() as stream:
        for line in stream:
            event=json.loads(line);s=event['source'];entry=dict(event)
            entry['source']=citation(s['package'],s['file'],event['line'],s['function'],s['source_sha256'])
            if event['kind']=='argument_binding':
                target=function_source(event['target']);entry['callee_source']=citation(**target)
                entry['binding']=dict(formal_index=event['formal_index'],projection=event.get('projection'))
            events[event['id']]=entry
    print('Cited events and source bytes verified:',len(events),flush=True)
    root='gem-api-memory-flows';index=[];sums=[];count=0;native_count=0;seen=set();inputs={}
    a.archive.parent.mkdir(parents=True,exist_ok=True)
    temporary=a.archive.with_suffix(a.archive.suffix+'.tmp')
    with temporary.open('wb') as raw,gzip.GzipFile(fileobj=raw,mode='wb',filename='',mtime=0,compresslevel=9) as zipped,tarfile.open(fileobj=zipped,mode='w|',format=tarfile.PAX_FORMAT) as archive:
        def add(name,data):
            info=tarfile.TarInfo(root+'/'+name);info.size=len(data);info.mode=0o644;info.mtime=0;info.uid=info.gid=0;info.uname=info.gname=''
            archive.addfile(info,io.BytesIO(data));sums.append(hashlib.sha256(data).hexdigest()+'  '+name+'\n')
        directory=tarfile.TarInfo(root+'/');directory.type=tarfile.DIRTYPE;directory.mode=0o755;directory.mtime=0;archive.addfile(directory)
        combined=hashlib.sha256()
        for part in layout['gem-api-memory-flows']['parts']:
            path=base/part['path'];assert sha(path)==part['sha256'];inputs[part['path']]=part['sha256'];part_count=0
            with path.open('rb') as stream:
                for original in stream:
                    combined.update(original);row=json.loads(original);chain_id=hashlib.sha256(original.rstrip(b'\n')).hexdigest()
                    assert chain_id not in seen;seen.add(chain_id)
                    chain=[dict(events[e],step=i) for i,e in enumerate(row['event_chain'])]
                    assert chain and chain[0]['function']==row['entry_function_id']
                    entry=function_source(row['entry_function_id'])
                    registration_package=next((k for k in prefixes if row['registration_id'].startswith(k+':')),None)
                    if registration_package is None and row['registration_id'].startswith('saved:'):
                        registration_package=row['gem']+'@'+row['version']
                    if registration_package is None and row['registration_id'].startswith('catalogue:'):
                        root_id=row['registration_id'].removeprefix('catalogue:').split(':binding:',1)[0]
                        with (base.parents[1]/'static-catalog/argument-inventory-roots.jsonl').open() as roots:
                            root_row=next(json.loads(line) for line in roots if json.loads(line)['entry_id']==root_id)
                        registration_package=root_row['gem']+'@'+root_row['source_variants'].split(';')[0]
                    assert registration_package in packages,row['registration_id']
                    native=row['memory_kind'] in NATIVE
                    record=dict(row,chain_id=chain_id,native_primitive=native,
                        snapshot=dict(status=snapshot['status'],checkpoint=snapshot['checkpoint'],function_evaluations=snapshot['function_evaluations'],fixed_point_reached=snapshot['fixed_point_reached']),
                        api_entry_source=citation(**entry),registration_source=citation(registration_package,row['registration_file'],row['registration_line']),flow=chain)
                    # The ordered embedded flow retains every ID; omit a duplicate ID vector.
                    del record['event_chain']
                    slug=lambda value:re.sub(r'[^a-zA-Z0-9_.-]','_',value)
                    name='chains/'+slug(row['gem'])+'/'+slug(row['version'])+'/'+chain_id+'.json'
                    add(name,(json.dumps(record,sort_keys=True,separators=(',',':'))+'\n').encode());index.append(dict(path=name,chain_id=chain_id,gem=row['gem'],version=row['version'],receiver=row['receiver'],method=row['method'],argument_index=row['argument_index'],memory_kind=row['memory_kind'],operand_role=row['operand_role'],native_primitive=native))
                    count+=1;part_count+=1;native_count+=native
                    if count%10000==0:print('Packaged chain files:',count,flush=True)
            assert part_count==part['records']
        assert combined.hexdigest()==layout['gem-api-memory-flows']['concatenated_sha256']
        assert count==layout['gem-api-memory-flows']['records']==snapshot['flow_records']
        assert native_count==snapshot['native_flow_records']
        inputs['gem-api-memory-flow-events.jsonl']=sha(base/'gem-api-memory-flow-events.jsonl')
        inputs['source-manifest.json']=sha(base/'source-manifest.json')
        inputs['gem-api-memory-flow-snapshot.json']=sha(base/'gem-api-memory-flow-snapshot.json')
        manifest=dict(format_version=1,chain_files=count,native_primitive_chain_files=native_count,distinct_apis_ignoring_version=snapshot['distinct_apis_ignoring_version'],
            source_files_cited=len(used_sources),events_cited=len(events),snapshot_status=snapshot['status'],fixed_point_reached=snapshot['fixed_point_reached'],
            input_sha256=inputs,indices='argument_index, call_site_parameters.index and binding.formal_index are zero-based; source lines are one-based.',
            contents='One JSON file per saved API/argument/operand flow. Each embeds the entire event chain, pinned source hashes, source lines, registration and C entrypoint citations. These package existing checkpoint facts.')
        add('manifest.json',encoded(manifest));add('snapshot.json',encoded(snapshot))
        add('index.jsonl',''.join(json.dumps(r,sort_keys=True,separators=(',',':'))+'\n' for r in index).encode())
        add('cited-sources.json',encoded([dict(package=k,file=f,**{n:v for n,v in file_maps[k][f].items() if n!='file'}) for k,f in sorted(used_sources)]))
        add('README.txt',b'Each chains/<gem>/<version>/<chain_id>.json is one saved argument-to-memory flow.\nThe complete flow is embedded in order, with source citations for every step.\nindex.jsonl maps API names to chain files. SHA256SUMS checks every payload.\nThe original interrupted-checkpoint status is retained in manifest.json and snapshot.json.\n')
        add('SHA256SUMS',''.join(sums).encode())
    temporary.replace(a.archive)
    report=dict(manifest,archive_sha256=sha(a.archive),archive_bytes=a.archive.stat().st_size)
    a.archive.with_suffix(a.archive.suffix+'.json').write_bytes(encoded(report))
    print(json.dumps(report,indent=2,sort_keys=True),flush=True)


if __name__=='__main__':main()
