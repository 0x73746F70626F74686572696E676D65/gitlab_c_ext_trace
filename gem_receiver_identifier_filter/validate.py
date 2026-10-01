"""Independently verify ordered subset integrity and every decision count."""
import collections
import csv
import gzip
import hashlib
import json
from pathlib import Path

HERE = Path(__file__).resolve().parent


def main():
    summary = json.loads((HERE / 'summary.json').read_text())
    for record in summary['inputs']:
        assert hashlib.sha256(Path(record['path']).read_bytes()).hexdigest() == record['sha256']
    input_path = Path(summary['inputs'][0]['path'])
    with (HERE / 'filtered_matches.csv').open(newline='') as f:
        kept = list(csv.DictReader(f))
    with gzip.open(HERE / 'filtered_matches.csv.gz', 'rt', newline='') as f:
        compressed = list(csv.DictReader(f))
    assert kept == compressed
    numbers = [int(r['input_row']) for r in kept]
    assert numbers == sorted(set(numbers))
    by_number = {int(r['input_row']): r for r in kept}
    counts = collections.Counter()
    reasons = collections.Counter()
    auth = collections.Counter()
    with gzip.open(input_path, 'rt', newline='') as inf, gzip.open(HERE / 'decisions.csv.gz', 'rt', newline='') as df:
        reader = csv.DictReader(inf)
        decisions = iter(csv.DictReader(df))
        for number, row in enumerate(reader, 2):
            decision = next(decisions)
            assert int(decision['input_row']) == number
            status = decision['decision']
            assert status in {'kept', 'receiver', 'argument'}
            counts[status] += 1
            reasons[(status, decision['reason'])] += 1
            if status == 'kept':
                out = by_number[number]
                assert all(out[k] == v for k, v in row.items()), ('Changed input field', number)
                assert out['receiver'] and out['resolved_gem'] == out['gem']
                assert out['expression_kind'] == 'identifier' and out['expression']
                assert out['receiver'] == decision['receiver']
                assert out['resolved_gem'] == decision['resolved_gem']
                auth[out['auth']] += 1
            else:
                assert number not in by_number
        assert next(decisions, None) is None
    assert sum(counts.values()) == summary['rows_in']
    assert len(kept) == counts['kept'] == summary['rows_kept']
    assert counts['receiver'] == summary['dropped_for_receiver']
    assert counts['argument'] == summary['dropped_for_literal_argument']
    assert auth['unauthenticated'] + auth['conditional_anonymous'] == summary['anonymous_kept']
    assert auth['unknown'] == summary['unknown_kept']
    assert dict(auth) == summary['kept_by_auth']
    expected_reasons = {(r['decision'], r['reason']): r['rows'] for r in summary['drop_and_keep_reasons']}
    assert dict(reasons) == expected_reasons
    assert summary['literal_argument_drops'] == reasons[('argument', 'literal_argument')]
    assert summary['empty_argument_drops'] == reasons[('argument', 'empty_or_splat_obscured_argument')]
    assert summary['other_non_identifier_argument_drops'] + summary['literal_argument_drops'] + summary['empty_argument_drops'] == counts['argument']
    result = {'status': 'passed', 'input_rows_verified': sum(counts.values()), 'kept_rows_verified': len(kept),
              'all_original_fields_preserved': True, 'auth_labels_unchanged': True,
              'partition_and_reason_counts_verified': True, 'entrypoints_rewalked': False, 'target_code_executed': False}
    (HERE / 'validation.json').write_text(json.dumps(result, indent=2) + '\n')
    print(json.dumps(result))


if __name__ == '__main__':
    main()
