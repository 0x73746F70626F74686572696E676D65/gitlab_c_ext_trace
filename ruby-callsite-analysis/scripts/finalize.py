#!/usr/bin/env python3
"""Add source citations to every receiver/argument edge; normalize artifact counts."""
import argparse,collections,hashlib,json
from pathlib import Path

def rows(p):
    with p.open() as f:
        for line in f:
            if line.strip():yield json.loads(line)
def write(p,r):p.write_text(json.dumps(r,indent=2,sort_keys=True)+'\n')
def main():
    ap=argparse.ArgumentParser();ap.add_argument('--out',type=Path,required=True);a=ap.parse_args();summary=json.loads((a.out/'summary.json').read_text())
    library={r['flow_id']:r for path in sorted((a.out/'c-flow-library').glob('*.jsonl')) for r in rows(path)}
    files={r['file']:r for r in rows(a.out/'files.jsonl')};groups={r['id']:r for r in rows(a.out/'api-groups.jsonl')};counts=collections.defaultdict(set);bindings=collections.Counter();api_sites=collections.defaultdict(list);records=[]
    def cite(e):
        f=files[e['file']];e['source_sha256']=f['sha256']
        if f['scope']=='gem_wrapper':e['source_package']=dict(gem=f['gem'],version=f['locked_version'],file=f['file'].split('/',2)[-1],package_sha256=f['package_sha256'],source_url=f['source_url'])
        else:e['source_permalink']='https://gitlab.com/gitlab-org/gitlab/-/blob/'+summary['gitlab_commit']+'/'+e['file']+'#L'+str(e['line'])
    for path in sorted((a.out/'callsites').rglob('*.json')):
        r=json.loads(path.read_text())
        for e in r['receiver']['proof']:cite(e)
        for h in r['native_flows']:
            for e in h['ruby_binding_path']:cite(e)
            group=groups[h['native_api_group']];api_sites[group['id']].append(dict(callsite_id=r['callsite_id'],file=r['source']['file'],line=r['source']['line'],ruby_method=r['method'],ruby_argument_index=h['ruby_argument_index'],native_argument_index=h['native_argument_index'],via=h['via'],c_flow_ids=h['c_flow_ids']));counts[group['gem']].add(r['callsite_id']);bindings[group['gem']]+=1
            h['native_api']['registration_arities']=group['arities'];h['native_api']['receiver_resolution']=group['receiver_resolution']
            operands={}
            for fid in h['c_flow_ids']:
                f=library[fid];operand=dict(memory_kind=f['memory_kind'],memory_operation=f['memory_operation'],operand_role=f['operand_role'],sink_type=f['sink_type'],call_site=f['call_site'],call_site_parameters=f['call_site_parameters'])
                key=json.dumps(operand,sort_keys=True,separators=(',',':'))
                operands.setdefault(key,operand)
            h['memory_call_sites']=[operands[key] for key in sorted(operands)]
            h['c_flow_library']='c-flow-library/*.jsonl (join by flow_id)'
            h['complete_c_chain_archive']='argument-taint-analysis/packages/gem-api-memory-flow-chains.tar.gz (chain filename is c_flow_id + .json)'
            if r['method']=='new' and h['native_api']['method']=='initialize' and h['via']=='native_direct':h['construction']='Class.new passes these actual arguments to the new instance native initialize'
        write(path,r);records.append(r)
    with (a.out/'callsites.jsonl').open('w') as f:
        for r in records:f.write(json.dumps(r,sort_keys=True,separators=(',',':'))+'\n')
    with (a.out/'api-callsite-map.jsonl').open('w') as stream:
        for api in sorted(groups.values(),key=lambda v:v['id']):
            row=dict(api_group=api['id'],gem=api['gem'],version=api['version'],owner=api['owner'],method=api['method'],kinds=api['kinds'],input_c_flow_ids=api['flow_ids'],callsites=api_sites[api['id']])
            stream.write(json.dumps(row,sort_keys=True,separators=(',',':'))+'\n')
    summary['matched_native_api_groups']=sum(bool(sites) for sites in api_sites.values())
    summary.pop('per_gem',None);summary['native_argument_bindings_per_gem']=dict(sorted(bindings.items()));summary['unique_callsites_per_gem']={g:len(ids) for g,ids in sorted(counts.items())}
    summary['matched_c_flow_records']=sum(1 for p in (a.out/'c-flow-library').glob('*.jsonl') for _ in rows(p))
    summary['ruby_scope']='All tracked .rb/.rake/.ru files, including tests/fixtures; embedded template languages excluded'
    summary['c_corpus_status']='Complete saved witnesses from interrupted native analysis checkpoint; original native census was not closed'
    summary['parser_error_files']=sum(r['parser_error'] for r in files.values());write(a.out/'summary.json',summary)
if __name__=='__main__':main()
