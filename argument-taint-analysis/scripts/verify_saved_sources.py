#!/usr/bin/env python3
"""Verify exact byte recovery of every older saved native source file."""
import argparse, collections, json
from pathlib import Path

def main():
    ap=argparse.ArgumentParser();ap.add_argument('--out',type=Path,required=True);ap.add_argument('--native-data',type=Path,required=True)
    a=ap.parse_args(); manifest=json.loads((a.out/'source-manifest.json').read_text())
    by_hash=collections.defaultdict(list)
    for p in manifest:
        for s in p['source_files']:
            by_hash[(p['gem'],p['version'],s['sha256'])].append(dict(variant=p.get('source_variant','published'),file=s['file']))
    ledger=[]
    for line in (a.native_data/'c_files.jsonl').open():
        r=json.loads(line); matches=by_hash[(r['gem_name'],r['version'],r['sha256'])]
        ledger.append(dict(file_id=r['file_id'],gem=r['gem_name'],version=r['version'],saved_path=r['path'],sha256=r['sha256'],
            status='exact_bytes_restored' if matches else 'saved_bytes_not_restored',matches=matches))
    with (a.out/'saved-source-byte-reconciliation.jsonl').open('w') as f:
        for r in ledger:f.write(json.dumps(r,sort_keys=True)+'\n')
    report=dict(saved_files=len(ledger),statuses=dict(sorted(collections.Counter(r['status'] for r in ledger).items())),
        missing_by_gem=dict(sorted(collections.Counter(r['gem'] for r in ledger if not r['matches']).items())))
    (a.out/'saved-source-verification.json').write_text(json.dumps(report,indent=2,sort_keys=True)+'\n')
    scavenged=json.loads((a.out/'scavenge-summary.json').read_text()) if (a.out/'scavenge-summary.json').exists() else {}
    collection=dict(source_variants=len(manifest),gem_names=len({p['gem'] for p in manifest}),
        native_source_files=sum(len(p['source_files']) for p in manifest),
        source_bytes=sum(s['bytes'] for p in manifest for s in p['source_files']),
        published_packages=sum(not p.get('git_commit') for p in manifest),
        recorded_repositories=sum(bool(p.get('git_commit')) for p in manifest),
        pinned_gitlinks=sum(len(p.get('gitlinks',[])) for p in manifest),
        recorded_vendor_checkouts=sum(len(p.get('vendored_sources',[])) for p in manifest),
        scavenged_files=scavenged.get('files'),scavenged_native_datasets=scavenged.get('native_evidence_files'),
        scavenged_registration_ids=len(scavenged.get('registration_ids',[])),
        saved_source_verification=report)
    (a.out/'collection-summary.json').write_text(json.dumps(collection,indent=2,sort_keys=True)+'\n')
    print(json.dumps(report,indent=2,sort_keys=True))

if __name__=='__main__':main()
