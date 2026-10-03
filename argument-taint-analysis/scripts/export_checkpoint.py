#!/usr/bin/env python3
"""Export existing checkpoint facts; do not resume or run the solver."""
import argparse, collections, csv, hashlib, json
from pathlib import Path
from index_cache import load_index
from trace import Index, sink_model, PARSERS, walk, args, callee, txt


def dump(path, rows):
    with path.open('w') as stream:
        for row in rows:
            stream.write(json.dumps(row, sort_keys=True, separators=(',', ':'))+'\n')


def digest(path):
    h=hashlib.sha256()
    with path.open('rb') as stream:
        for block in iter(lambda:stream.read(4*1024*1024), b''):
            h.update(block)
    return h.hexdigest()


def dump_parts(out, name, rows, limit=32*1024*1024):
    directory=out/name;directory.mkdir(exist_ok=True)
    for path in directory.glob('part-*.jsonl'):path.unlink()
    parts=[];stream=None;size=0;count=0;path=None;combined=hashlib.sha256()
    def close():
        if stream:
            stream.close();parts.append(dict(path=str(path.relative_to(out)),bytes=size,records=count,sha256=digest(path)))
    try:
        for row in rows:
            line=(json.dumps(row,sort_keys=True,separators=(',',':'))+'\n').encode();combined.update(line)
            if stream is None or size+len(line)>limit and count:
                close();path=directory/f'part-{len(parts)+1:04d}.jsonl';stream=path.open('wb');size=0;count=0
            stream.write(line);size+=len(line);count+=1
    finally:close()
    return dict(parts=parts,records=sum(p['records'] for p in parts),concatenated_sha256=combined.hexdigest())


def operands(event, role):
    if event['kind']!='call':
        return []
    expression=event['expression']
    source=('void _snapshot(){'+expression+';}').encode()
    node=PARSERS['c'].parse(source).root_node
    calls=[n for n in walk(node) if n.type=='call_expression']
    if not calls:
        return []
    call=calls[0]; actuals=args(call); model=sink_model(event.get('target',''),len(actuals))
    if not model:
        return []
    return [dict(index=i,expression=txt(actuals[i],source))
            for i,r in model[1] if r==role and i<len(actuals)]


def main():
    ap=argparse.ArgumentParser()
    for name in ['repo','checkpoint','index','manifest','native_data','out']:
        ap.add_argument('--'+name.replace('_','-'),type=Path,required=True)
    a=ap.parse_args(); a.out.mkdir(parents=True,exist_ok=True)
    generation=a.checkpoint/(a.checkpoint/'CURRENT').read_text().strip()
    meta=json.loads((generation/'metadata.json').read_text())
    assert digest(Path(__file__).with_name('trace.py'))==meta['identity']['files'][str(Path(__file__).with_name('trace.py'))]
    data=load_index(a.index); index=Index()
    index.functions=data['functions'];index.roots=data['roots'];index.files=data['files'];index.global_methods=data['global_methods']
    for fid,fn in index.functions.items():index.names[(fn['package'],fn['name'])].append(fid)
    index.global_roots();index.saved_roots(a.repo,a.native_data)
    manifest=json.loads(a.manifest.read_text());index.link_packages(a.repo,manifest);index.source_includes(manifest)
    for r in index.roots:r['targets']=index.resolve(r['package'],r['file'],r['c_function'])
    index.normalize_roots()
    assert hashlib.sha256(json.dumps(index.roots,sort_keys=True).encode()).hexdigest()==meta['identity']['roots_sha256'],'root inventory differs from checkpoint'
    print('Checkpoint root identities verified:',len(index.roots),flush=True)
    by_target=collections.defaultdict(list)
    for r in index.roots:
        if r['arity']:
            for target in r['targets']:by_target[target].append(r)
    pending={fid for _,fid in meta['queue']}; records=[]; used_events=set(); seen=set()
    with (generation/'functions.jsonl').open() as stream:
        for line in stream:
            row=json.loads(line); target=row['function']
            if target not in by_target:continue
            for key,path in row['sinks']:
                (formal,projection),kind,role=key
                if kind=='field_store':continue
                for root in by_target[target]:
                    argument=None
                    if root['arity']>0 and 1<=formal<=root['arity']:argument=formal-1
                    elif root['arity'] in {-1,-2} and formal==1:argument=projection if isinstance(projection,int) else '*'
                    if argument is None or isinstance(argument,int) and argument<0:continue
                    unique=(root['entry_id'],target,str(argument),kind,role,tuple(path))
                    if unique in seen:continue
                    seen.add(unique);used_events.update(path)
                    records.append(dict(registration_id=root['entry_id'],gem=root['gem'],version=root['version'],receiver=root['receiver'],
                        method=root['method'],registration=root['registration'],c_entry_function=root['c_function'],
                        entry_function_id=target,registration_file=root['file'],registration_line=root['line'],
                        argument_index=argument,memory_kind=kind,operand_role=role,event_chain=path,
                        root_pending_update=target in pending))
    print('Saved API argument flows:',len(records),flush=True)
    events={}
    with (generation/'events.jsonl').open() as stream:
        for line in stream:
            event=json.loads(line)
            if event['id'] in used_events:events[event['id']]=event
    assert set(events)==used_events,'missing checkpoint witness events'
    parameters={};api_groups=collections.defaultdict(list)
    for row in records:
        chain=[events[e] for e in row['event_chain']];tail=chain[-1];fn=index.functions[tail['function']]
        assert chain[0]['function']==row['entry_function_id']
        row.update(memory_operation=tail.get('target',tail['kind']),call_site=dict(file=fn['file'],line=tail['line'],
            function=fn['name'],function_id=fn['id'],package=fn['package'],source_sha256=fn['source_sha256'],expression=tail['expression']),
            call_depth=sum(e['kind']=='argument_binding' for e in chain),sink_type=tail['kind'])
        parameter_key=(tail['id'],row['operand_role'])
        if parameter_key not in parameters:parameters[parameter_key]=operands(tail,row['operand_role'])
        row['call_site_parameters']=parameters[parameter_key]
        api_groups[(row['gem'],row['version'],row['receiver'],row['method'],row['registration'])].append(row)
    records.sort(key=lambda r:(r['gem'],r['version'],r['receiver'],r['method'],r['registration_id'],str(r['argument_index']),r['memory_kind'],r['operand_role'],r['event_chain']))
    layouts={'gem-api-memory-flows':dump_parts(a.out,'gem-api-memory-flows',records)}
    native={'allocation','copy','memory_set','memory_read','release','format_buffer'}
    native_records=[r for r in records if r['memory_kind'] in native]
    layouts['gem-api-native-memory-flows']=dump_parts(a.out,'gem-api-native-memory-flows',native_records)
    (a.out/'gem-api-memory-flow-files.json').write_text(json.dumps(layouts,indent=2,sort_keys=True)+'\n')
    def enrich(event):
        fn=index.functions[event['function']]
        return dict(event,source=dict(package=fn['package'],file=fn['file'],function=fn['name'],source_sha256=fn['source_sha256']))
    dump(a.out/'gem-api-memory-flow-events.jsonl',(enrich(events[e]) for e in sorted(events)))
    apis=[dict(gem=g,version=v,receiver=o,method=m,registration=k,argument_indices=sorted({str(r['argument_index']) for r in rs}),
        memory_kinds=sorted({r['memory_kind'] for r in rs}),flow_records=len(rs),registration_ids=sorted({r['registration_id'] for r in rs}))
        for (g,v,o,m,k),rs in sorted(api_groups.items())]
    (a.out/'gem-api-memory-flow-apis.json').write_text(json.dumps(apis,indent=2,sort_keys=True)+'\n')
    def api_key(r,version=True):
        kind='singleton' if r['registration']=='rb_define_singleton_method' else 'module_function' if r['registration'] in {'rb_define_module_function','rb_define_global_function'} else 'instance'
        return (r['gem'],r['version'],r['receiver'],r['method'],kind) if version else (r['gem'],r['receiver'],r['method'],kind)
    summary=dict(status='interrupted_checkpoint_snapshot',fixed_point_reached=False,work_commit='2b0bc9e9229755b1f7a9233c8cd67f75d1f83af5',
        checkpoint=generation.name,function_evaluations=meta['analyses'],pending_functions=len(pending),
        registered_roots=len(index.roots),flow_records=len(records),native_flow_records=len(native_records),events=len(events),
        distinct_versioned_apis=len({api_key(r) for r in records}),distinct_apis_ignoring_version=len({api_key(r,False) for r in records}),
        native_distinct_versioned_apis=len({api_key(r) for r in native_records}),native_distinct_apis_ignoring_version=len({api_key(r,False) for r in native_records}),
        witnessed_gems=len({r['gem'] for r in records}),call_depth_limit=None,max_saved_witness_call_depth=max((r['call_depth'] for r in records),default=0),
        definition='Every explicit API argument memory-operand witness saved in the intact checkpoint; ordinary field stores excluded. Static may-taint facts; solver had not closed.',
        event_join='event_chain IDs join gem-api-memory-flow-events.jsonl; argument_index and call_site_parameters.index are zero-based; * means a variadic explicit argument.',
        checkpoint_identity=meta['identity'])
    (a.out/'gem-api-memory-flow-snapshot.json').write_text(json.dumps(summary,indent=2,sort_keys=True)+'\n')
    names=['gem-api-memory-flow-files.json','gem-api-memory-flow-events.jsonl','gem-api-memory-flow-apis.json','gem-api-memory-flow-snapshot.json']
    names.extend(p['path'] for dataset in layouts.values() for p in dataset['parts'])
    (a.out/'gem-api-memory-flow-SHA256SUMS').write_text(''.join(digest(a.out/n)+'  '+n+'\n' for n in names))
    print(json.dumps({k:v for k,v in summary.items() if k!='checkpoint_identity'},indent=2),flush=True)


if __name__=='__main__':main()
