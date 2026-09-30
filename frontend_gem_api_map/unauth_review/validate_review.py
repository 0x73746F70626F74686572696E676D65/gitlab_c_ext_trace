#!/usr/bin/env python3
"""Check the review overlay against every original candidate and site."""
import argparse
import collections
import csv
import hashlib
import json
from pathlib import Path

from review_candidates import jsonl


def main():
    p = argparse.ArgumentParser()
    for name in ('source', 'inventory', 'baseline', 'output'):
        p.add_argument('--' + name, type=Path, required=True)
    a = p.parse_args()
    summary = json.loads((a.output / 'summary.json').read_text())
    assert hashlib.sha256(a.inventory.read_bytes()).hexdigest() == summary['api_inventory_sha256']
    assert hashlib.sha256((a.baseline / 'summary.json').read_bytes()).hexdigest() == summary['baseline_summary_sha256']
    assert hashlib.sha256((a.baseline / 'entrypoints.jsonl.gz').read_bytes()).hexdigest() == summary['baseline_entrypoints_sha256']
    original = {e['id']: e for e in jsonl(a.baseline / 'entrypoints.jsonl.gz')
                if e['auth']['classification'] == 'unauthenticated' and e['matches']}
    records = jsonl(a.output / 'reviews.jsonl.gz')
    assert len(records) == len(original) == 191
    assert {r['entrypoint_id'] for r in records} == set(original)
    api = {a['id']: a for a in json.loads(a.inventory.read_text())}
    files = jsonl(a.output / 'source_files.jsonl')
    for f in files:
        assert hashlib.sha256((a.source / f['file']).read_bytes()).hexdigest() == f['sha256'], f['file']
    lines = {}
    def check_location(site):
        file, line = site['file'], site['line']
        assert file.endswith(('.rb', '.ru'))
        if file not in lines:
            lines[file] = (a.source / file).read_text(errors='replace').splitlines()
        assert 1 <= line <= len(lines[file]), (file, line)
        if site.get('method'):
            token = '[' if site['method'] == '[]' else site['method']
            assert token in lines[file][line - 1], (file, line, token)
    site_counts = collections.Counter()
    for r in records:
        base = original[r['entrypoint_id']]
        assert r['gitlab_commit_sha'] == summary['gitlab_commit_sha']
        assert len(r['original_match_reviews']) == len(base['matches'])
        assert r['examined_bodies'] <= summary['body_cap_per_trace']
        for review, match in zip(r['original_match_reviews'], base['matches']):
            assert all(review[k] == match[k] for k in ('file', 'line', 'method', 'receiver'))
            assert review['baseline_api_ids'] == match['api_ids']
            sets = [set(review[k]) for k in ('supported_api_ids', 'rejected_api_ids', 'unresolved_api_ids')]
            assert set.union(*sets) == set(match['api_ids'])
            assert not any(sets[i] & sets[j] for i in range(3) for j in range(i + 1, 3))
            assert review['status'] == ('supported' if sets[0] else 'unresolved' if sets[2] else 'rejected')
            site_counts[review['status']] += 1
            check_location(review)
        for site in r['qualified_sites']:
            check_location(site)
            assert site['supported_api_ids']
            assert 0 <= site['hop_depth'] <= summary['helper_depth_cap']
            assert len(site['helper_path']) == site['hop_depth']
            assert set(site['supported_api_ids']) <= set(api)
            value = site['receiver_inference']
            for aid in site['supported_api_ids']:
                namespace = api[aid]['namespace']
                assert namespace == value['type'] or (namespace == 'CGI::EscapeExt' and value['type'] == 'CGI')
        assert r['supported_api_ids'] == sorted({i for s in r['qualified_sites'] for i in s['supported_api_ids']})
        assert r['api_status'] == ('supported' if r['qualified_sites'] else 'unresolved' if
            any(s['unresolved_api_ids'] for s in r['original_match_reviews']) else 'original_matches_rejected')
        assert r['entrypoint_status'] == ('callback_block' if r['action'].startswith('@') else
            'registered_action' if r['routes'] else 'public_method_registration_unresolved')
    assert dict(site_counts) == summary['original_site_review_counts']
    for key, field in [('entrypoint_status_counts', 'entrypoint_status'), ('api_status_counts', 'api_status')]:
        assert dict(collections.Counter(r[field] for r in records)) == summary[key]
    assert dict(collections.Counter(r['reviewed_auth']['classification'] for r in records)) == summary['reviewed_auth_counts']
    assert sum(bool(r['qualified_sites']) for r in records) == summary['qualified_candidates']
    assert sum(r['newly_qualified'] for r in records) == summary['newly_qualified_candidates']
    for classification in ('unauthenticated', 'unknown'):
        assert sum(bool(r['qualified_sites']) and r['entrypoint_status'] == 'registered_action' and
                   r['reviewed_auth']['classification'] == classification for r in records) == summary[
                       'registered_' + ('unknown_auth' if classification == 'unknown' else 'unauthenticated') + '_qualified_candidates']
    gaps = jsonl(a.output / 'gaps.jsonl.gz')
    assert dict(collections.Counter(g['kind'] for g in gaps)) == summary['gap_counts']
    assert {g['entrypoint_id'] for g in gaps} <= set(original)
    assert all(r['gap_count'] == sum(g['entrypoint_id'] == r['entrypoint_id'] for g in gaps) for r in records)
    with open(a.output / 'reviews.csv', newline='') as f:
        csv_records = list(csv.DictReader(f))
    assert len(csv_records) == len(original)
    assert {r['entrypoint_id'] for r in csv_records} == set(original)
    report = {'status': 'passed', 'candidates_reviewed': 191, 'original_sites_verified': sum(site_counts.values()),
              'source_hashes_verified': len(files), 'qualified_candidates': summary['qualified_candidates'],
              'checks': ['baseline preserved', 'inventory unchanged', 'all candidates/sites covered', 'API ID partitions',
                         'source hashes and match locations', 'helper bounds', 'CSV agreement', 'aggregate counts', 'gap references'],
              'limitation': 'Integrity and synthetic tests do not prove runtime paths or anonymous admission.'}
    (a.output / 'validation.json').write_text(json.dumps(report, indent=2) + '\n')
    print(json.dumps(report, indent=2))


if __name__ == '__main__':
    main()
