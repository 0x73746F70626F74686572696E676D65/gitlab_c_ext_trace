#!/usr/bin/env python3
"""Check corpus, root, operand-witness and output consistency without target execution."""
import argparse, collections, csv, hashlib, json
from pathlib import Path
from trace import sink_model,package_key

def main():
    ap=argparse.ArgumentParser(); ap.add_argument('--repo',type=Path,required=True); ap.add_argument('--out',type=Path,required=True)
    a=ap.parse_args(); out=a.out
    def rows(name): return [json.loads(l) for l in (out/name).open()]
    source_manifest=json.loads((out/'source-manifest.json').read_text()); source_files={}; line_counts={}
    for p in source_manifest:
        key=package_key(p)
        for s in p['source_files']:
            b=(Path(p['directory'])/s['file']).read_bytes()
            assert hashlib.sha256(b).hexdigest()==s['sha256'],(key,s['file'])
            source_files[(key,s['file'])]=s; line_counts[(key,s['file'])]=len(b.splitlines())
    scanned=list(csv.DictReader((a.repo/'static-catalog/files-scanned.csv').open()))
    for s in scanned:
        key=s['gem']+'@'+s['source_variants'].split(';')[0]
        assert source_files[(key,s['file'])]['sha256']==s['sha256']
    files=rows('files.jsonl'); assert len(files)==len(source_files)
    assert {(r['package'],r['file']) for r in files}==set(source_files)
    funcs={r['id']:r for r in rows('functions.jsonl')}; events={r['id']:r for r in rows('events.jsonl')}
    roots={r['entry_id']:r for r in rows('roots.jsonl')}; witnesses=rows('witnesses.jsonl'); apis=rows('apis-by-registration.jsonl')
    callbacks=rows('callback-table-bindings.jsonl');pointer_arguments=rows('function-pointer-arguments.jsonl')
    rejected_abis=rows('call-abi-boundaries.jsonl')
    for rejected in rejected_abis:
        assert rejected['event'] in events and rejected['target'] in funcs
        assert events[rejected['event']]['function']==rejected['function']
        assert rejected['formal_arguments']==len(funcs[rejected['target']]['parameters'])
        assert rejected['actual_arguments']<rejected['formal_arguments'] if rejected['variadic'] else rejected['actual_arguments']!=rejected['formal_arguments']
    def valid_target(target):
        return sink_model(target.removeprefix('@memory:'),100) is not None if target.startswith('@memory:') else target in funcs
    for binding in callbacks:
        source=source_files[(binding['package'],binding['file'])]
        assert binding['source_sha256']==source['sha256']
        assert 1<=binding['line']<=line_counts[(binding['package'],binding['file'])]
        assert all(valid_target(target) for targets in binding['fields'].values() for target in targets)
    for binding in pointer_arguments:
        assert 0<=binding['formal_index']<len(funcs[binding['function']]['parameters'])
        assert all(valid_target(target) for target in binding['targets'])
    assert len(roots)==len(rows('roots.jsonl')),'duplicate registration identities'
    for e in events.values():
        f=funcs[e['function']]; assert 1<=e['line']<=line_counts[(f['package'],f['file'])]
        if e['kind']=='argument_binding':
            target=funcs[e['target']]; assert 0<=e['formal_index']<len(target['parameters'])
    count=collections.Counter(); kinds=collections.Counter()
    for w in witnesses:
        root=roots[w['entry_id']]; assert w['events']; assert root['arity']!=0
        argument=w['argument_index']; assert argument=='*' or isinstance(argument,int) and argument>=0
        if root['arity']>0: assert isinstance(argument,int) and argument<root['arity']
        path=[events[e] for e in w['events']]; assert path[0]['function'] in root['targets']
        tail=path[-1]; f=funcs[tail['function']]
        assert (w['site_file'],w['site_line'],w['site_function'],w['source_sha256'])==(f['file'],tail['line'],f['name'],f['source_sha256'])
        if tail['kind']=='call':
            assert sink_model(tail['target'],100) is not None or tail['target'] in {'Data_Make_Struct','TypedData_Make_Struct'}
        else: assert tail['kind'] in {'assignment','update','declaration','array_extent','new_expression','delete_expression'}
        assert w['call_depth']==sum(e['kind']=='argument_binding' for e in path)
        count[w['entry_id']]+=1; kinds[w['kind']]+=1
    for api in apis: assert api['witnesses']==count[api['entry_id']]
    summary=json.loads((out/'summary.json').read_text())
    api_csv=list(csv.DictReader((out/'apis.csv').open()))
    assert len(api_csv)==summary['distinct_versioned_apis']
    assert len(witnesses)==summary['witnesses']; assert summary['fixed_point_reached'] and summary['call_depth_limit'] is None
    report=dict(status='passed',source_packages=len(source_manifest),source_files_verified=len(source_files),
        current_catalogue_files_verified=len(scanned),registered_roots=len(roots),witnesses_checked=len(witnesses),
        events_checked=len(events),callback_bindings_checked=len(callbacks),function_pointer_arguments_checked=len(pointer_arguments),rejected_call_abis_checked=len(rejected_abis),witness_kinds=dict(sorted(kinds.items())),
        checks=['package source SHA256','all current catalogue hashes','all source files indexed','unique root IDs',
            'explicit argument positions','first witness event bound to API target','all formal bindings exist',
            'all source line ranges','memory operand classifications','all output counts agree'],
        validation_scope='Structural and semantic-fixture validation; not a proof of whole-program analysis soundness or path feasibility.')
    (out/'validation.json').write_text(json.dumps(report,indent=2,sort_keys=True)+'\n')
    print(json.dumps(report,indent=2,sort_keys=True))

if __name__=='__main__': main()
