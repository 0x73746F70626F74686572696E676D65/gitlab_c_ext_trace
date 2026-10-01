"""Check saved-table integrity without running Ruby or redoing call resolution."""
import collections
import csv
import gzip
import hashlib
import json
from pathlib import Path

HERE = Path(__file__).resolve().parent
REPO = HERE.parent


def main():
    summary = json.loads((HERE / 'summary.json').read_text())
    inventory = json.loads((REPO / summary['entrypoint_inventory']).read_text())['entrypoints']
    entries = {e['id']: e for e in inventory}
    assert len(entries) == len(inventory), 'Duplicate inventory identities'
    with (REPO / summary['call_argument_table']).open(newline='') as f:
        catalog = {i: row for i, row in enumerate(csv.DictReader(f), 2)}
    for key, sha_key in [('entrypoint_inventory', 'entrypoint_inventory_sha256'),
                         ('call_argument_table', 'call_argument_table_sha256')]:
        assert hashlib.sha256((REPO / summary[key]).read_bytes()).hexdigest() == summary[sha_key]
    auth = collections.Counter()
    count = 0
    matched_names = set()
    matched_rows = set()
    matched_entries = set()
    depth_counts = collections.Counter()
    with gzip.open(HERE / 'matches.csv.gz', 'rt', newline='') as f:
        for row in csv.DictReader(f):
            ep = entries[row['entrypoint']]
            table = catalog[int(row['argument_table_line'])]
            assert row['auth'] == ep['auth']['classification']
            assert row['anonymous_access'] == str(ep['anonymous_access'])
            for out, src in [('gem', 'gem'), ('ruby_method', 'ruby_method_name'),
                             ('argument_index', 'argument_index'), ('slot', 'slot')]:
                assert row[out] == table[src], (out, row['entrypoint'])
            depth = int(row['call_chain_depth'])
            assert 0 <= depth <= 4
            chain = json.loads(row['call_chain'])
            assert len(chain) == depth + 1
            assert chain[-1]['file'] == row['file']
            assert int(row['line']) >= chain[-1]['line']
            assert all(not h['method'].endswith(('#send', '#public_send', '#__send__', '#method_missing')) for h in chain)
            assert row['expression_kind'] in {'literal', 'identifier', 'expression', 'not_visible'}
            assert bool(row['expression']) == (row['expression_kind'] != 'not_visible')
            count += 1
            auth[row['auth']] += 1
            matched_names.add(row['ruby_method'])
            matched_rows.add(int(row['argument_table_line']))
            matched_entries.add(row['entrypoint'])
            depth_counts[depth] += 1
    assert count == summary['matches']
    assert dict(auth) == summary['matches_by_auth']
    assert auth['unknown'] == summary['unknown_matches']
    assert auth['unauthenticated'] + auth['conditional_anonymous'] == summary['anonymous_matches']
    assert len(matched_entries) == summary['entrypoints_with_matches']
    assert set(summary['methods_with_no_match']) == {r['ruby_method_name'] for r in catalog.values()} - matched_names
    walked = set()
    statuses = collections.Counter()
    per_entry_matches = 0
    with gzip.open(HERE / 'entrypoints_walked.jsonl.gz', 'rt') as f:
        for line in f:
            row = json.loads(line)
            assert row['entrypoint'] in entries and row['entrypoint'] not in walked
            assert row['auth'] == entries[row['entrypoint']]['auth']['classification']
            walked.add(row['entrypoint'])
            statuses[row['status']] += 1
            per_entry_matches += row.get('matches', 0)
    assert walked == set(entries)
    assert statuses['walked'] == summary['entrypoints_walked']
    assert per_entry_matches == count
    stops = collections.Counter()
    with gzip.open(HERE / 'unresolved_stops.jsonl.gz', 'rt') as f:
        for line in f:
            row = json.loads(line)
            assert row['entrypoint'] in entries
            assert 0 <= row['depth'] <= 4
            stops[row['reason']] += 1
    assert dict(stops) == summary['unresolved_stops']
    with (HERE / 'methods_with_no_match.csv').open(newline='') as f:
        unmatched = {int(r['argument_table_line']) for r in csv.DictReader(f)}
    assert unmatched == set(catalog) - matched_rows
    result = {'status': 'passed', 'matches_verified': count, 'inventory_records_verified': len(walked),
              'unresolved_stops_verified': sum(stops.values()), 'matches_by_depth': dict(sorted(depth_counts.items())),
              'target_code_executed': False}
    (HERE / 'validation.json').write_text(json.dumps(result, indent=2) + '\n')
    print(json.dumps(result))


if __name__ == '__main__':
    main()
