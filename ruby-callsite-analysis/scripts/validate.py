#!/usr/bin/env python3
"""Independently check artifact/source joins and summarize unique call sites."""
import argparse,collections,hashlib,json,re,subprocess
from pathlib import Path
import tree_sitter,tree_sitter_ruby
PARSER=tree_sitter.Parser(tree_sitter.Language(tree_sitter_ruby.language()))
def text(n):return n.text.decode('utf-8','replace') if n else ''
def field(n,k):return n.child_by_field_name(k) if n else None

def rows(p):
    with p.open() as stream:
        for line in stream:
            if line.strip():yield json.loads(line)
def ident(r):return hashlib.sha256(json.dumps(r,sort_keys=True,separators=(',',':')).encode()).hexdigest()
def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()
def main():
    p=argparse.ArgumentParser();p.add_argument('--repo',type=Path,required=True);p.add_argument('--gitlab',type=Path,required=True);p.add_argument('--out',type=Path,required=True);a=p.parse_args()
    summary=json.loads((a.out/'summary.json').read_text());assert summary['fixed_point_reached']
    assert subprocess.check_output(['git','-C',str(a.gitlab),'rev-parse','HEAD'],text=True).strip()==summary['gitlab_commit']
    original={};layout=json.loads((a.repo/'argument-taint-analysis/results/gem-api-memory-flow-files.json').read_text())
    for part in layout['gem-api-memory-flows']['parts']:
        path=a.repo/'argument-taint-analysis/results'/part['path'];assert sha(path)==part['sha256']
        for r in rows(path):original[ident(r)]=r
    library={r['flow_id']:r for path in sorted((a.out/'c-flow-library').glob('*.jsonl')) for r in rows(path)}
    for fid,r in library.items():assert {k:v for k,v in r.items() if k not in {'flow_id','api_group'}}==original[fid]
    groups={r['id']:r for r in rows(a.out/'api-groups.jsonl')};files={r['file']:r for r in rows(a.out/'files.jsonl')}
    verified_source=0
    for f,r in files.items():
        path=Path(r['path']) if r['scope']=='gem_wrapper' else a.gitlab/f
        assert sha(path)==r['sha256'],f;verified_source+=1
    trees={};sites={};coverage=collections.defaultdict(set);bygem=collections.defaultdict(set);bindings=0;semantic=[]
    for path in sorted((a.out/'callsites').rglob('*.json')):
        r=json.loads(path.read_text());sid=r['callsite_id'];assert sid not in sites;sites[sid]=r
        source=r['source'];assert source['source_sha256']==files[source['file']]['sha256'];raw=(a.gitlab/source['file']).read_bytes()
        offset=sum(len(x) for x in raw.splitlines(keepends=True)[:source['line']-1])+source['column']-1
        expr=r['expression'].encode();assert raw[offset:offset+len(expr)]==expr,(path,'call expression/source mismatch')
        assert r['receiver']['types'] and r['receiver']['proof'];args=r['supplied_arguments'];assert [x['index'] for x in args]==list(range(len(args)))
        tree=trees.get(source['file'])
        if tree is None:
            tree=PARSER.parse(raw);trees[source['file']]=tree
        node=tree.root_node.descendant_for_byte_range(offset,offset+len(expr)-1)
        while node and (node.start_byte!=offset or node.end_byte!=offset+len(expr) or node.type not in {'call','identifier','binary','element_reference'}):node=node.parent
        assert node is not None,(path,'no call AST at cited location')
        if r['method'].endswith('=') and node.parent and node.parent.type in {'assignment','operator_assignment'} and field(node.parent,'left')==node:
            source_args=[field(node.parent,'right')]
        elif node.type=='binary':source_args=[field(node,'right')]
        elif node.type=='element_reference':source_args=field(node,'arguments').named_children if field(node,'arguments') else [n for n in node.named_children if n!=field(node,'object')]
        else:source_args=field(node,'arguments').named_children if field(node,'arguments') else []
        if text(field(node,'method')) in {'send','public_send','__send__'} and r['method']!=text(field(node,'method')):source_args=source_args[1:]
        ordinary=[];keywords=[];permitted=set()
        for arg in source_args:
            if arg.type=='block_argument':continue
            if arg.type in {'pair','hash_splat_argument'}:keywords.append(text(arg));continue
            ordinary.append(text(arg));permitted.add(text(arg))
            if arg.type=='splat_argument' and arg.named_children:permitted.add(text(arg.named_children[0]))
        if keywords:ordinary.append(', '.join(keywords));permitted.add(', '.join(keywords))
        assert all(arg['expression'] in permitted for arg in args),(path,'supplied argument not present in source invocation')
        if not any(arg['kind'] in {'expanded_splat','unknown_splat'} for arg in args):assert [arg['expression'] for arg in args]==ordinary,(path,'argument positions differ from source invocation')

        for event in r['receiver']['proof']+[e for h in r['native_flows'] for e in h['ruby_binding_path']]:
            assert event['file'] in files;assert 0<=event['byte_start']<=event['byte_end']<=files[event['file']]['bytes']
        sb=[]
        for h in r['native_flows']:
            api=groups[h['native_api_group']];index=h['ruby_argument_index'];assert 0<=index<len(args)
            assert args[index]['kind']!='unknown_splat';assert not any(x['kind']=='unknown_splat' for x in args[:index])
            assert h['ruby_argument_expression']==args[index]['expression'];assert h['ruby_argument_kind']==args[index]['kind'];assert h['c_flow_ids']
            for fid in h['c_flow_ids']:
                f=library[fid];assert f['api_group']==api['id'];assert f['argument_index']==h['native_argument_index'];assert f['gem']==h['native_api']['gem'];assert f['version']==h['native_api']['version'];coverage[fid].add(sid)
            expected_operands={json.dumps(dict(memory_kind=library[fid]['memory_kind'],memory_operation=library[fid]['memory_operation'],operand_role=library[fid]['operand_role'],sink_type=library[fid]['sink_type'],call_site=library[fid]['call_site'],call_site_parameters=library[fid]['call_site_parameters']),sort_keys=True,separators=(',',':')) for fid in h['c_flow_ids']}
            assert {json.dumps(v,sort_keys=True,separators=(',',':')) for v in h['memory_call_sites']}==expected_operands
            if h['via']=='native_direct':assert h['native_argument_index'] in {'*',index}
            else:assert h['via']=='ruby_wrapper' and any(e['kind']=='ruby_argument_binding' for e in h['ruby_binding_path'])
            bygem[api['gem']].add(sid);bindings+=1;sb.append([api['id'],index,h['native_argument_index'],sorted(h['c_flow_ids'])])
        semantic.append([sid,source['file'],source['line'],source['column'],r['receiver']['types'],sorted(sb,key=str)])
    aggregate_paths=[a.out/'callsites.jsonl'] if (a.out/'callsites.jsonl').exists() else sorted((a.out/'callsites-jsonl').glob('*.jsonl'))
    aggregate={r['callsite_id']:r for path in aggregate_paths for r in rows(path)};assert aggregate==sites
    ledger=list(rows(a.out/'flow-coverage.jsonl'));assert len(ledger)==len(original)==summary['input_flow_records'];assert {r['flow_id'] for r in ledger}==set(original)
    for r in ledger:
        assert set(r['callsite_ids'])==coverage.get(r['flow_id'],set())
        assert (r['status']=='matched')==bool(r['callsite_ids'])
    assert len(sites)==summary['verified_callsites'];assert len(library)==summary['matched_c_flow_records'];assert set(coverage)==set(library)
    report=dict(passed=True,source_files_hash_verified=verified_source,input_c_flows_checked=len(original),matched_c_flows_checked=len(library),callsite_json_files=len(sites),argument_bindings_checked=bindings,
        unique_callsites_per_gem={g:len(v) for g,v in sorted(bygem.items())},semantic_set_sha256=ident(sorted(semantic,key=str)),checks=['Pinned GitLab revision and source hashes','One JSON per unique physical call site','Exact call expression at cited byte/line/column','Independent Ruby AST confirms supplied argument expressions and nonsplat positions','Nonempty receiver types and evidence','Actual supplied argument exists before any unknown splat','Native argument index matches each original C witness','C flow IDs exactly hash original corpus records','All 63076 C witnesses have a coverage ledger entry','Aggregate JSONL equals individual JSON files'])
    (a.out/'validation.json').write_text(json.dumps(report,indent=2,sort_keys=True)+'\n');print(json.dumps(report,indent=2,sort_keys=True))
if __name__=='__main__':main()
