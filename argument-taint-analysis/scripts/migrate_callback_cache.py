#!/usr/bin/env python3
"""Reuse an inert callback cache only after proving scanner code is unchanged."""
import argparse,ast,hashlib,json
from pathlib import Path
from trace import Index,package_key
from checkpoint import digest

def scanner_tree(path):
    tree=ast.parse(path.read_text());selected=[]
    for node in tree.body:
        if isinstance(node,(ast.Assign,ast.AnnAssign,ast.Import,ast.ImportFrom)):
            selected.append(node)
        elif isinstance(node,ast.ClassDef) and node.name=='Index':selected.append(node)
        elif isinstance(node,ast.FunctionDef) and node.name not in {'main','output'}:selected.append(node)
    return ast.dump(ast.Module(body=selected,type_ignores=[]),include_attributes=False)

def main():
    ap=argparse.ArgumentParser();ap.add_argument('--before',type=Path,required=True);ap.add_argument('--index',type=Path,required=True)
    ap.add_argument('--manifest',type=Path,required=True);ap.add_argument('--repo',type=Path,required=True);ap.add_argument('--audit',type=Path,required=True)
    a=ap.parse_args();current=Path(__file__).with_name('trace.py')
    assert scanner_tree(a.before)==scanner_tree(current),'Callback scanner/resolver/model code changed'
    manifest=json.loads(a.manifest.read_text());index=Index()
    index.files=[dict(package=package_key(p)) for p in manifest if p['source_files']];index.link_packages(a.repo,manifest)
    identity=dict(index=digest(a.index),manifest=digest(a.manifest),parser_requirements=digest(current.with_name('requirements.txt')),dependencies=index.package_dependencies)
    def key(implementation):return hashlib.sha256(json.dumps(dict(identity,implementation=implementation),sort_keys=True).encode()).hexdigest()
    before,after=digest(a.before),digest(current);cache=a.index.with_suffix('.callbacks.jsonl');temporary=cache.with_suffix('.migration.tmp')
    with cache.open() as original,temporary.open('w') as replacement:
        metadata=json.loads(next(original));assert metadata['cache_key']==key(before),'Cache does not match verified preceding scanner'
        replacement.write(json.dumps(dict(cache_key=key(after)))+'\n')
        for line in original:replacement.write(line)
    temporary.replace(cache)
    a.audit.write_text(json.dumps(dict(status='passed',scanner_and_model_ast_identical=True,before_implementation_sha256=before,after_implementation_sha256=after,callback_cache_sha256=digest(cache)),indent=2,sort_keys=True)+'\n')
    print('Callback scanner and models unchanged; cache identity migrated')

if __name__=='__main__':main()
