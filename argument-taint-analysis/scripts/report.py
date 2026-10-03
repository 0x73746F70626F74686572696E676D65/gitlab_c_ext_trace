#!/usr/bin/env python3
"""Join the computed witnesses to API identities and every saved registration."""
import argparse, collections, csv, json, re
from pathlib import Path

def main():
    ap=argparse.ArgumentParser()
    ap.add_argument('--repo',type=Path,required=True); ap.add_argument('--out',type=Path,required=True)
    ap.add_argument('--native-data',type=Path,required=True); ap.add_argument('--prior',type=Path)
    a=ap.parse_args(); out=a.out
    def rows(name): return [json.loads(l) for l in (out/name).open()]
    roots=rows('roots.jsonl'); root_ids={r['entry_id']:r for r in roots}
    witnesses=rows('witnesses.jsonl'); events={r['id']:r for r in rows('events.jsonl')}
    apis=list(csv.DictReader((out/'apis.csv').open()))
    lock={(r['gem'],r['version']) for r in csv.DictReader((a.repo/'static-catalog/locked-gems.csv').open())}
    operand_rows=[]; seen=set()
    for w in witnesses:
        r=root_ids[w['entry_id']]; tail=events[w['events'][-1]]
        kind='singleton' if r['registration']=='rb_define_singleton_method' else 'module_function' if r['registration'] in {'rb_define_module_function','rb_define_global_function'} else 'instance'
        row=dict(gem=w['gem'],version=w['version'],receiver=w['receiver'],method=w['method'],kind=kind,
            primary_lock=(w['gem'],w['version']) in lock,argument_index=w['argument_index'],memory_kind=w['kind'],
            c_entry_function=r['c_function'],registration_file=r['file'],registration_line=r['line'],
            operand_role=w['operand_role'],memory_operation=tail.get('target',tail['kind']),
            operand_expression=w['site_expression'],source_file=w['site_file'],source_line=w['site_line'],
            c_function=w['site_function'],call_depth=w['call_depth'],registration_id=w['entry_id'],
            source_sha256=w['source_sha256'],event_chain=json.dumps(w['events'],separators=(',',':')))
        key=tuple(str(v) for v in row.values())
        if key not in seen: seen.add(key); operand_rows.append(row)
    def write(name,items):
        with (out/name).open('w',newline='') as f:
            w=csv.DictWriter(f,list(items[0])); w.writeheader(); w.writerows(items)
    unique=collections.defaultdict(list)
    for r in apis: unique[(r['gem'],r['receiver'],r['method'],r['kind'])].append(r)
    unique_rows=[dict(gem=g,receiver=o,method=m,kind=k,
        versions=';'.join(sorted({r['version'] for r in rs})),
        c_functions=';'.join(sorted({f for r in rs for f in r['c_functions'].split(';')})),
        memory_kinds=';'.join(sorted({f for r in rs for f in r['memory_kinds'].split(';')})),
        registration_ids=';'.join(sorted({f for r in rs for f in r['registration_ids'].split(';')})))
        for (g,o,m,k),rs in sorted(unique.items())]
    write('apis-unique.csv',unique_rows)
    write('api-argument-memory-operands.csv',operand_rows)
    native={'allocation','copy','memory_set','memory_read','release','format_buffer'}
    with (out/'native-api-argument-memory-operands.jsonl').open('w') as f:
        for row in operand_rows:
            if row['memory_kind'] in native:
                record=dict(row,event_chain=json.loads(row['event_chain']))
                record['flow']=[events[e] for e in record['event_chain']]
                f.write(json.dumps(record,sort_keys=True)+'\n')
    gems=sorted({r['gem'] for r in apis}); per_gem=[]
    for g in gems:
        selected=[r for r in apis if r['gem']==g]
        per_gem.append(dict(gem=g,versions=';'.join(sorted({r['version'] for r in selected})),
            primary_lock_apis=sum((g,r['version']) in lock for r in selected),
            all_versioned_apis=len(selected),apis_ignoring_version=len({(r['receiver'],r['method'],r['kind']) for r in selected})))
    write('counts-by-gem.csv',per_gem)
    native_apis=list(csv.DictReader((out/'apis-native-low-level-operations.csv').open()))
    native_counts=[]
    for g in sorted({r['gem'] for r in native_apis}):
        selected=[r for r in native_apis if r['gem']==g]
        native_counts.append(dict(gem=g,versions=';'.join(sorted({r['version'] for r in selected})),
            primary_lock_apis=sum((g,r['version']) in lock for r in selected),
            all_versioned_apis=len(selected),apis_ignoring_version=len({(r['receiver'],r['method'],r['kind']) for r in selected})))
    write('counts-by-gem-native-low-level-operations.csv',native_counts)

    gems_by_id={r['gem_id']:r for l in (a.native_data/'gems.jsonl').open() if (r:=json.loads(l))}
    saved_files={r['file_id']:r['path'] for l in (a.native_data/'c_files.jsonl').open() if (r:=json.loads(l))}
    registrations={}; evidence=rows('scavenged-native-evidence.jsonl')
    for data in evidence:
        name=Path(data['member']).name.removesuffix('.gz')
        if name not in {'c_registrations.jsonl','native_registrations.jsonl'}: continue
        for line in Path(data['path']).open():
            try: r=json.loads(line)
            except ValueError: continue
            key=r['registration_id']
            if key not in registrations: registrations[key]=dict(record=r,datasets=[])
            registrations[key]['datasets'].append(data['sha256'])
    saved={r['registration_id']:r for r in rows('saved-registration-reconciliation.jsonl')}
    norm=lambda s:re.sub(r'\s+','',s or '')
    alias_roots=collections.defaultdict(list)
    for r in roots:
        if r['registration']=='rb_define_alias': alias_roots[(r['gem'],r['version'],r['line'],norm(r['receiver_expression']))].append(r)
    ledger=[]
    for key,item in sorted(registrations.items()):
        r=item['record']; gem=gems_by_id.get(r['gem_id'],{})
        row=dict(registration_id=key,gem=gem.get('name'),version=gem.get('version'),registration=r['registration_api'],
            datasets=sorted(set(item['datasets'])))
        if key in saved and (saved[key]['entries'] or r['registration_api']!='rb_define_alias'):
            row.update(status=saved[key]['status'],entries=saved[key]['entries'])
        elif r['registration_api']=='rb_define_alias':
            candidates=alias_roots[(gem.get('name'),gem.get('version'),r['line'],norm(r.get('receiver_expression')))]
            name=r.get('ruby_name')
            if not name:
                strings=re.findall(r'"(?:\\.|[^"\\])*"',r.get('context',''))
                if strings:
                    try:name=json.loads(strings[0])
                    except ValueError:pass
            if name:candidates=[x for x in candidates if x['method']==name]
            oldpath=saved_files.get(r.get('file_id'),'')
            if oldpath:
                candidates=[x for x in candidates if oldpath.endswith('/'+x['file'])]
            row.update(status='fresh_alias' if candidates else 'unresolved_saved_alias',entries=[x['entry_id'] for x in candidates])
        else: row.update(status='unreconciled_saved_registration',entries=[])
        row['root_statuses']=sorted({root_ids[x]['status'] for x in row['entries']})
        ledger.append(row)
    with (out/'all-scavenged-registration-reconciliation.jsonl').open('w') as f:
        for row in ledger: f.write(json.dumps(row,sort_keys=True)+'\n')
    report=dict(distinct_apis_ignoring_version=len(unique_rows),saved_registration_ids=len(ledger),saved_registration_statuses=dict(sorted(collections.Counter(r['status'] for r in ledger).items())),
        api_argument_operand_rows=len(operand_rows),per_gem_counts=per_gem,
        native_api_argument_operand_rows=sum(r['memory_kind'] in native for r in operand_rows),
        native_distinct_apis_ignoring_version=sum(r['apis_ignoring_version'] for r in native_counts),
        native_witnessed_gems=len(native_counts))
    if a.prior and a.prior.exists():
        present={(r['gem'],r['version'],r['method']) for r in apis}; checks=[]
        for old in csv.DictReader(a.prior.open()):
            name=re.split(r'[.#]',old['api'])[-1]
            checks.append(dict(gem=old['gem'],version=old['version'],api=old['api'],method=name,
                rediscovered=(old['gem'],old['version'],name) in present))
        report['prior_census_checks']=checks
        report['prior_apis_rediscovered']=sum(r['rediscovered'] for r in checks)
    (out/'delivery-report.json').write_text(json.dumps(report,indent=2,sort_keys=True)+'\n')
    print(json.dumps({k:v for k,v in report.items() if k not in {'per_gem_counts','prior_census_checks'}},indent=2,sort_keys=True))

if __name__=='__main__': main()
