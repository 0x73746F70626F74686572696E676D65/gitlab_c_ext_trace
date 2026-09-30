#!/usr/bin/env python3
"""Check record integrity and source locations; no application execution."""
import argparse
import collections
import csv
import gzip
import hashlib
import json
import subprocess
from pathlib import Path


def rows(path):
    opener = gzip.open if path.suffix == '.gz' else open
    with opener(path, 'rt') as f:
        for line in f:
            yield json.loads(line)


def main():
    p = argparse.ArgumentParser(description=__doc__)
    for name in ('source', 'inventory', 'output'):
        p.add_argument('--' + name, type=Path, required=True)
    a = p.parse_args()
    s = json.loads((a.output / 'summary.json').read_text())
    sha = subprocess.check_output(['git', '-C', str(a.source), 'rev-parse', 'HEAD']).decode().strip()
    assert sha == s['gitlab_commit_sha']
    assert hashlib.sha256(a.inventory.read_bytes()).hexdigest() == s['api_inventory_sha256']
    apis = json.loads(a.inventory.read_text())
    assert list(rows(a.output / 'api_catalog.jsonl')) == apis
    api_ids = {x['id'] for x in apis}
    files = {r['file']: r for r in rows(a.output / 'files_examined.jsonl')}
    assert len(files) == s['parsed_files']
    for file, r in files.items():
        assert hashlib.sha256((a.source / file).read_bytes()).hexdigest() == r['sha256'], file
    bodies = {r['id']: r for r in rows(a.output / 'bodies.jsonl.gz')}
    assert len(bodies) == s['method_or_block_bodies']
    counts, used, qualified_used, ids = collections.Counter(), set(), set(), set()
    expected_flattened = collections.Counter()
    source_lines = {}
    def check_location(file, line):
        assert file in files, file
        if file not in source_lines:
            source_lines[file] = (a.source / file).read_text(errors='replace').splitlines()
        assert 1 <= line <= len(source_lines[file]), (file, line)
    for e in rows(a.output / 'entrypoints.jsonl.gz'):
        assert e['id'] not in ids, e['id']
        ids.add(e['id'])
        assert e['gitlab_commit_sha'] == sha
        assert e['examined_body_count'] <= s['helper_method_cap_per_entrypoint']
        assert all(uid in bodies for uid in e['roots'])
        check_location(e['source']['file'], e['source']['line'])
        auth = e['auth']['classification']
        assert auth in {'authenticated', 'unauthenticated', 'unknown'}
        assert e['matched_api_ids'] == sorted({x for m in e['matches'] for x in m['api_ids']})
        assert e['qualified_matched_api_ids'] == sorted({x for m in e['matches'] if m['qualified'] for x in m['api_ids']})
        used.update(e['matched_api_ids'])
        qualified_used.update(e['qualified_matched_api_ids'])
        counts['entrypoints_examined'] += 1
        counts[auth + '_entrypoints'] += 1
        counts[auth + '_with_match'] += bool(e['matches'])
        counts[auth + '_with_qualified_match'] += bool(e['qualified_matched_api_ids'])
        counts['unmatched_entrypoints'] += not bool(e['matches'])
        counts['entrypoints_without_qualified_matches'] += not bool(e['qualified_matched_api_ids'])
        counts['match_sites'] += len(e['matches'])
        for m in e['matches']:
            assert set(m['api_ids']) <= api_ids
            assert 0 <= m['hop_depth'] <= s['helper_depth_cap']
            assert len(m['helper_path']) == m['hop_depth']
            assert m['confidence'] == (('direct' if m['hop_depth'] == 0 else 'helper') if m['qualified'] else 'name-only')
            check_location(m['file'], m['line'])
            # Each recorded method spelling must occur on the reported source line.
            token = '[' if m['method'] == '[]' else m['method']
            assert token in source_lines[m['file']][m['line'] - 1], (m['file'], m['line'], m['method'])
            for aid in m['api_ids']:
                expected_flattened[(e['id'], aid, m['file'], m['line'], m['hop_depth'], m['confidence'])] += 1
            for hop in m['helper_path']:
                assert hop['from'] in bodies and hop['target'] in bodies
                check_location(hop['file'], hop['line'])
            counts[m['confidence'] + '_match_sites'] += 1
    assert dict(counts) == s['counts'], (counts, s['counts'])
    assert {r['id'] for r in rows(a.output / 'zero_match_apis.jsonl')} == api_ids - used
    assert {r['id'] for r in rows(a.output / 'zero_qualified_match_apis.jsonl')} == api_ids - qualified_used
    assert len(api_ids - used) == s['apis_with_zero_entrypoint_matches']
    assert len(api_ids - qualified_used) == s['apis_with_zero_qualified_entrypoint_matches']
    with open(a.output / 'entrypoints.csv', newline='') as f:
        csv_rows = list(csv.DictReader(f))
    assert {r['entrypoint_id'] for r in csv_rows} == ids
    assert len(csv_rows) == len(ids)
    flattened = collections.Counter()
    with gzip.open(a.output / 'matches.csv.gz', 'rt', newline='') as f:
        for r in csv.DictReader(f):
            assert r['gitlab_commit_sha'] == sha
            flattened[(r['entrypoint_id'], r['api_id'], r['file'], int(r['line']), int(r['hop_depth']), r['confidence'])] += 1
    assert flattened == expected_flattened
    for kind, n in s['coverage_record_counts'].items():
        records = list(rows(a.output / f'coverage_{kind}.jsonl.gz'))
        assert len(records) == n
        for r in records:
            if 'entrypoint_id' in r:
                assert r['entrypoint_id'] in ids
    report = {'status': 'passed', 'gitlab_commit_sha': sha, 'entrypoints': len(ids),
              'parsed_source_hashes_verified': len(files), 'match_sites_verified': counts['match_sites'],
              'flattened_api_match_rows_verified': sum(flattened.values()),
              'checks': ['inventory unchanged', 'source revision/hashes', 'unique entrypoint IDs',
                         'API catalog/IDs', 'source line locations/method spelling', 'helper depth and paths',
                         'CSV/JSONL agreement', 'aggregate counts', 'zero-match sets', 'coverage referential integrity'],
              'limitation': 'Integrity and synthetic behavior checks do not establish semantic precision or recall.'}
    (a.output / 'validation.json').write_text(json.dumps(report, indent=2) + '\n')
    print(json.dumps(report, indent=2))


if __name__ == '__main__':
    main()
