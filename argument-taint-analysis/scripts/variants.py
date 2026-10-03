#!/usr/bin/env python3
"""Write explicit alternative sink scopes without rerunning or inventing flows."""
import argparse, collections, csv, json
from pathlib import Path

def main():
    ap=argparse.ArgumentParser();ap.add_argument('--repo',type=Path,required=True);ap.add_argument('--out',type=Path,required=True)
    args=ap.parse_args(); rows=[json.loads(l) for l in (args.out/'apis-by-registration.jsonl').open()]
    lock={(r['gem'],r['version']) for r in csv.DictReader((args.repo/'static-catalog/locked-gems.csv').open())}
    def group(selected):
        groups=collections.defaultdict(list)
        for r in selected:
            kind='singleton' if r['registration']=='rb_define_singleton_method' else 'module_function' if r['registration'] in {'rb_define_module_function','rb_define_global_function'} else 'instance'
            groups[(r['gem'],r['version'],r['receiver'],r['method'],kind)].append(r)
        return [dict(gem=g,version=v,receiver=o,method=m,kind=k,c_functions=';'.join(sorted({r['c_function'] for r in rs})),
            memory_kinds=';'.join(sorted({k for r in rs for k in r['memory_kinds'].split(';')})),
            registration_ids=';'.join(sorted(r['entry_id'] for r in rs))) for (g,v,o,m,k),rs in sorted(groups.items())]
    native={'allocation','copy','memory_set','memory_read','release','format_buffer'}
    scopes={'including-field-stores':rows,
        'named-memory-functions':[r for r in rows if any(k not in {'field_store','buffer_store','stack_allocation'} for k in r['memory_kinds'].split(';'))],
        'native-low-level-operations':[r for r in rows if native.intersection(r['memory_kinds'].split(';'))]}
    counts={}
    for scope,selected in scopes.items():
        all_=group(selected); primary=[r for r in all_ if (r['gem'],r['version']) in lock]
        for suffix,items in [('',all_),('-primary-lock',primary)]:
            with (args.out/f'apis-{scope}{suffix}.csv').open('w',newline='') as f:
                w=csv.DictWriter(f,list(all_[0]));w.writeheader();w.writerows(items)
        names=collections.defaultdict(list)
        for r in all_:names[(r['gem'],r['receiver'],r['method'],r['kind'])].append(r)
        unique=[dict(gem=g,receiver=o,method=m,kind=k,versions=';'.join(sorted({r['version'] for r in rs})),
                     c_functions=';'.join(sorted({v for r in rs for v in r['c_functions'].split(';')})),
                     memory_kinds=';'.join(sorted({v for r in rs for v in r['memory_kinds'].split(';')})),
                     registration_ids=';'.join(sorted({v for r in rs for v in r['registration_ids'].split(';')})))
                for (g,o,m,k),rs in sorted(names.items())]
        with (args.out/f'apis-{scope}-unique.csv').open('w',newline='') as f:
            w=csv.DictWriter(f,list(unique[0]));w.writeheader();w.writerows(unique)
        counts[scope]=dict(all_versions=len(all_),primary_lock=len(primary),apis_ignoring_version=len(unique))
    (args.out/'sink-scope-counts.json').write_text(json.dumps(counts,indent=2,sort_keys=True)+'\n')
    print(json.dumps(counts,indent=2,sort_keys=True))

if __name__=='__main__':main()
