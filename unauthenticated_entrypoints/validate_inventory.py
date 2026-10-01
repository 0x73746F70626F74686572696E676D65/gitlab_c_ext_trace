#!/usr/bin/env python3
"""Validate saved JSON and source provenance; no GitLab execution or requests."""
import argparse, collections, gzip, hashlib, json, subprocess
from pathlib import Path
from jsonschema import Draft202012Validator

def validate(directory, source=None):
    read=lambda name:json.loads((directory/name).read_text())
    whole=read('entrypoints.json');rows=whole['entrypoints'];meta=whole['metadata']
    assert len({r['id'] for r in rows})==len(rows), 'Duplicate record IDs'
    by_id={r['id']:r for r in rows};evidence=read('evidence.json');coverage=read('coverage.json')
    schema=Draft202012Validator(read('inventory.schema.json'))
    errors=list(schema.iter_errors(whole))
    assert not errors, '\n'.join(str(e) for e in errors[:5])
    assert len(rows)==meta['counts']['registered_entrypoint_records']
    assert dict(collections.Counter(r['auth']['classification'] for r in rows))==meta['counts']['by_auth']
    sha=meta['gitlab_commit_sha']
    for r in rows:
        assert r['gitlab_commit_sha']==sha
        assert r['auth']['runtime_verified'] is False
        for key in r['auth']['evidence_ids']:assert key in evidence['evidence'], key
        for key in r['auth']['gap_ids']:assert key in evidence['gaps'], key
        if 'callback_pipeline_id' in r['auth']:assert r['auth']['callback_pipeline_id'] in evidence['callback_pipelines']
        for key in r.get('transport_entrypoint_ids',[]):assert key in by_id
        expected=r['auth']['classification'] in {'unauthenticated','conditional_anonymous'} and r.get('response_kind')!='error_only'
        assert r['anonymous_access']==expected, r['id']
        if r['anonymous_access']:
            assert r['auth']['confidence']=='source_supported'
            assert r['registration_status']!='unresolved_registration'
            assert r['path'] and '<' not in r['path']
    partitions=[('unconditional.json','unauthenticated'),('conditional_anonymous.json','conditional_anonymous'),('authenticated.json','authenticated'),('unknown.json','unknown')]
    all_partition_ids=set()
    for filename,classification in partitions:
        payload=read(filename);ids={r['id'] for r in payload['entrypoints']}
        assert payload['count']==len(ids)
        assert ids=={r['id'] for r in rows if r['auth']['classification']==classification}
        assert not all_partition_ids.intersection(ids)
        all_partition_ids.update(ids)
        assert all(by_id[r['id']]==r for r in payload['entrypoints'])
    assert all_partition_ids==set(by_id)
    for filename,graphql_only in [('unauthenticated.json',None),('http_unauthenticated.json',False),('graphql_unauthenticated.json',True)]:
        payload=read(filename)
        expected={r['id'] for r in rows if r['anonymous_access'] and (graphql_only is None or r['type'].startswith('graphql')==graphql_only)}
        assert payload['count']==len(payload['entrypoints'])==len(expected)
        assert {r['id'] for r in payload['entrypoints']}==expected
        assert all(by_id[r['id']]==r for r in payload['entrypoints'])
    snapshot=coverage['committed_routing_snapshot_comparison']
    assert snapshot['available'] and len(snapshot['templates'])==snapshot['template_count']
    assert sum(x['matched_source_registration'] for x in snapshot['templates'])==snapshot['source_matched_templates']
    for row in snapshot['templates']:
        assert row['entrypoint_ids'] and all(i in by_id for i in row['entrypoint_ids'])
    gaps=coverage['gaps'];assert all(g.get('entrypoint_id') in by_id for g in gaps if 'entrypoint_id' in g)
    smoke=[]
    if sha=='d75e5afaa21d45bc04139d4a538ea5954be1ef4f':
        checks=[('/users/sign_in','GET','rails_action','unauthenticated'),('/api/graphql','POST','rails_action','unauthenticated'),('/api/v4/projects','POST','grape_endpoint','authenticated'),('/api/v4/projects/:id','GET','grape_endpoint','conditional_anonymous'),('/api/v4/version','GET','grape_endpoint','authenticated')]
        for path,verb,kind,classification in checks:
            selected=[r for r in rows if r['edition']=='ce' and r.get('path')==path and verb in r['http_methods'] and r['type']==kind]
            assert selected and all(r['auth']['classification']==classification for r in selected),(path,selected)
            smoke.append({'edition':'ce','path':path,'method':verb,'expected_auth':classification,'passed':True})
        assert meta['counts']['route_files_examined']==76
        assert snapshot['template_count']==5058
    checked_source_files=0
    if source:
        actual=subprocess.check_output(['git','-C',str(source),'rev-parse','HEAD'],text=True).strip()
        assert actual==sha
        assert not subprocess.check_output(['git','-C',str(source),'status','--porcelain','--untracked-files=no'],text=True).strip()
        files={r['file']:r for r in coverage['discovery_source_files']+coverage['source_files'] if not r['file'].startswith('external/')}
        for relative,record in files.items():
            assert hashlib.sha256((source/relative).read_bytes()).hexdigest()==record['sha256'],relative
        checked_source_files=len(files)
        drawn={r['file'] for r in coverage['route_file_expansions']}
        tracked=subprocess.check_output(['git','-C',str(source),'ls-files','-z'],text=True).split('\0')
        expected={f for f in tracked if f.startswith(('config/routes/','ee/config/routes/')) and f.endswith('.rb')}
        assert expected.issubset(drawn),expected-drawn
        baseline=directory.parent/'frontend_gem_api_map/entrypoints.jsonl.gz'
        if baseline.exists() and meta['baseline_sha256']:
            assert hashlib.sha256(baseline.read_bytes()).hexdigest()==meta['baseline_sha256']
            with gzip.open(baseline,'rt') as handle:old={json.loads(line)['id'] for line in handle}
            accounted={i for r in rows for i in r['baseline_ids']}|{r['baseline_id'] for r in coverage['baseline_records_without_reconstructed_registration']}
            assert old.issubset(accounted), 'Baseline discovery records lost'
    report={'gitlab_commit_sha':sha,'passed':True,'checks':['JSON schema','unique IDs','partition equality and disjointness','auth/evidence/callback/transport references','public list excludes unknown/dynamic/error-only records','all committed snapshot templates accounted for','aggregate counts','pinned source route smoke checks'],'records_validated':len(rows),'source_files_hash_verified':checked_source_files,'route_smoke_checks':smoke,'unit_tests_result_file':'test_results.json','generator_sha256':hashlib.sha256((directory/'build_inventory.py').read_bytes()).hexdigest(),'runtime_requests_or_application_execution':False,'auth_completeness_proven':False}
    (directory/'validation.json').write_text(json.dumps(report,indent=2)+'\n')
    print(json.dumps(report,indent=2))

if __name__=='__main__':
    parser=argparse.ArgumentParser();parser.add_argument('--directory',type=Path,default=Path(__file__).resolve().parent);parser.add_argument('--source',type=Path)
    args=parser.parse_args();validate(args.directory,args.source)
