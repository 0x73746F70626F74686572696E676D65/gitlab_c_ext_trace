#!/usr/bin/env python3
"""Validate registration source identity, without traversing argument/call paths."""
import argparse
import collections
import csv
import hashlib
import io
import json
from pathlib import Path

HERE = Path(__file__).resolve().parent
CATALOG = HERE.parent
INPUTS = ('argument-inventory-roots.jsonl', 'entry-points.csv', 'files-scanned.csv',
          'fetch-manifest.json', 'review-metadata/source-validation.json',
          'entry-argument-sites.jsonl', 'summary.json',
          'argument-inventory-dedup-collisions.jsonl',
          'review-metadata/unresolved-rows.jsonl',
          'scripts/entry_catalog.py', 'scripts/call_argument_inventory.py')


def sha(blob):
    return hashlib.sha256(blob).hexdigest()


def normalize_status(root):
    current = root['inventory_status']
    assert current in {'resolved', 'unresolved', 'unresolved_signature'}
    gaps = []
    if current == 'unresolved':
        gaps.append('function_binding_unresolved')
    elif current == 'unresolved_signature':
        gaps.append('parameter_signature_unresolved')
    historical_resolved = root['status'] == 'resolved'
    if historical_resolved != (current == 'resolved'):
        gaps.append('historical_and_current_status_differ')
    return gaps


def generate(catalog=CATALOG):
    blobs = {name: (catalog / name).read_bytes() for name in INPUTS}
    receipt = json.loads(blobs['review-metadata/source-validation.json'])
    assert receipt['result']['status'] == 'passed'
    for name in INPUTS:
        if name not in receipt['input_sha256']:
            continue
        assert sha(blobs[name]) == receipt['input_sha256'][name], name
    roots_raw = blobs['argument-inventory-roots.jsonl'].splitlines()
    entries = {r['entry_id']: r for r in csv.DictReader(io.StringIO(blobs['entry-points.csv'].decode()))}
    files = {(r['gem'], r['file']): r for r in csv.DictReader(io.StringIO(blobs['files-scanned.csv'].decode()))}
    manifest = {(r['gem'], r['locked_version']): r for r in json.loads(blobs['fetch-manifest.json'])}
    cache = {}

    def source(gem, file, line):
        record = files[gem, file]
        variant = record['source_variants'].split(';')[0]
        package = manifest[gem, variant]
        path = Path(package['source_directory']) / file
        if path not in cache:
            data = path.read_bytes()
            assert sha(data) == record['sha256'], str(path)
            cache[path] = data.splitlines()
        assert 0 < line <= len(cache[path]), (file, line)
        return record, package, cache[path][line - 1]

    rows, unresolved = [], []
    for number, raw in enumerate(roots_raw, 1):
        root = json.loads(raw)
        entry = entries[root['entry_id']]
        assert all(root[key] == value for key, value in entry.items()), root['entry_id']
        record, package, line = source(root['gem'], root['registration_file'], int(root['registration_line']))
        assert root['registration'].encode() in line, root['entry_id']
        definition_digest = ''
        if root['definition_file'] and root['definition_line']:
            definition, _, _ = source(root['gem'], root['definition_file'], int(root['definition_line']))
            definition_digest = definition['sha256']
        gaps = normalize_status(root)
        row = dict(entry_id=root['entry_id'], root_line=number, root_row_sha256=sha(raw),
                   root_evidence=f'../argument-inventory-roots.jsonl:{number}',
                   gem=root['gem'], version=root['version'], registration=root['registration'],
                   registration_file=root['registration_file'], registration_line=int(root['registration_line']),
                   registration_source_sha256=record['sha256'],
                   registration_line_sha256=sha(line), source_variants=record['source_variants'],
                   verified_locked_variant=package['locked_version'],
                   package_url=package['source_url'], package_sha256=package['sha256'],
                   source_identity_status='digest_and_registration_token_verified',
                   historical_binding_status=root['status'], current_binding_status=root['inventory_status'],
                   definition_reference_status=('digest_and_line_range_verified' if definition_digest else 'not_recorded'),
                   definition_source_sha256=definition_digest,
                   parameter_names_status=('recorded_not_semantically_revalidated' if root['parameter_names'] else 'not_recorded'),
                   evidence_status=('open_evidence_gap' if gaps else 'source_identity_verified_binding_claim_preserved'),
                   runtime_activation='not_established')
        rows.append(row)
        if gaps:
            unresolved.append(dict(entry_id=row['entry_id'], root_evidence=row['root_evidence'],
                                   root_row_sha256=row['root_row_sha256'], gaps=gaps,
                                   status='open_evidence_gap', interpretation='documentation_gap_not_vulnerability'))
    assert len(rows) == len(entries) == len({r['entry_id'] for r in rows})
    roots_by_id = {json.loads(raw)['entry_id']: json.loads(raw) for raw in roots_raw}
    argument_raw = blobs['entry-argument-sites.jsonl'].splitlines()
    argument_rows = [json.loads(raw) for raw in argument_raw]
    argument_ids = {r['entry_id'] for r in argument_rows}
    assert argument_ids <= entries.keys()
    argument_gaps = [json.loads(raw) for raw in blobs['review-metadata/unresolved-rows.jsonl'].splitlines()]
    assert len(argument_gaps) == len(argument_rows)
    for number, (row, raw, gap) in enumerate(zip(argument_rows, argument_raw, argument_gaps), 1):
        assert gap['inventory_line'] == number and gap['inventory_row_sha256'] == sha(raw)
        assert gap['status'] == 'open_evidence_gap'
        expected = {'local_checks_not_assessed', 'value_preservation_not_established',
                    'source_reinspection_not_performed'}
        root = roots_by_id[row['entry_id']]
        index = row['argument_index']
        names = root['parameter_names']
        fixed = (int(root['arity']) >= 0 and index < int(root['arity']) and
                 index + 1 < len(names) and names[index + 1] == row['parameter_name'])
        if not fixed:
            expected.add('exact_positional_extraction_not_serialized')
        if row['hop_count']:
            expected.add('per_hop_formal_identity_not_serialized')
        assert set(gap['gaps']) == expected and len(gap['gaps']) == len(expected)
    summary = json.loads(blobs['summary.json'])
    collisions = [json.loads(raw) for raw in blobs['argument-inventory-dedup-collisions.jsonl'].splitlines()]
    alternatives = [row for collision in collisions for row in collision['alternatives']]
    candidate_ids = argument_ids | {r['entry_id'] for r in alternatives}
    assert candidate_ids <= entries.keys()
    assert len(argument_rows) + len(alternatives) == summary['candidate_argument_slot_rows']
    assert len(candidate_ids) == summary['roots_with_rows']
    assert len(collisions) == summary['dedup_keys_with_distinct_alternatives']
    cross_tab = [dict(binding_status=status,
                      with_argument_rows=sum(r['inventory_status'] == status and r['entry_id'] in argument_ids
                                             for r in roots_by_id.values()),
                      without_argument_rows=sum(r['inventory_status'] == status and r['entry_id'] not in argument_ids
                                                for r in roots_by_id.values()))
                 for status in sorted({r['inventory_status'] for r in roots_by_id.values()})]
    distinctions = []
    if summary['roots_with_rows'] != len(argument_ids):
        distinctions.append(dict(field='summary.json:roots_with_rows',
                                  recorded_pre_deduplication=summary['roots_with_rows'],
                                  computed_representative_rows=len(argument_ids),
                                  status='explained_denominator_difference',
                                  cause='summary_counts_inventory.rows_before_representative_deduplication',
                                  evidence='../scripts/call_argument_inventory.py:480-519'))
    coverage = dict(registrations=len(rows), argument_rows=len(argument_rows),
                    registrations_with_argument_rows=len(argument_ids),
                    registrations_without_argument_rows=len(rows) - len(argument_ids),
                    binding_status_cross_tab=cross_tab, summary_denominator_distinctions=distinctions,
                    collision_alternative_rows=len(alternatives),
                    candidate_registration_ids_including_alternatives=len(candidate_ids),
                    registrations_only_in_alternatives=len(candidate_ids - argument_ids),
                    candidate_rows_including_alternatives=len(argument_rows) + len(alternatives),
                    argument_unresolved_ledger_rows_verified=len(argument_gaps),
                    registration_unresolved_ledger_rows_verified=len(unresolved),
                    denominators='registrations and selected argument rows are distinct populations',
                    absent_row_interpretation='no_selected_saved_row_not_absence_of_behavior_or_safety',
                    new_paths_or_semantic_claims=False)
    output = io.StringIO(newline='')
    writer = csv.DictWriter(output, fieldnames=list(rows[0]), lineterminator='\n')
    writer.writeheader()
    writer.writerows(rows)
    report = dict(status='passed', registrations=len(rows), source_files_verified=len(cache),
                  exact_entry_root_joins=True, unresolved_registration_rows=len(unresolved),
                  counts={key: dict(sorted(collections.Counter(r[key] for r in rows).items()))
                          for key in ('current_binding_status', 'historical_binding_status', 'definition_reference_status')},
                  overlapping_gap_counts=dict(sorted(collections.Counter(g for r in unresolved for g in r['gaps']).items())),
                  input_sha256={k: sha(v) for k, v in blobs.items()},
                  target_code_executed=False, call_or_argument_traces_added=False,
                  argument_ledger_completeness_verified=True,
                  explained_summary_denominator_distinctions=len(distinctions),
                  binding_semantics_revalidated=False)
    return {'rows.jsonl': ''.join(json.dumps(r, sort_keys=True) + '\n' for r in rows),
            'rows.csv': output.getvalue(),
            'unresolved-rows.jsonl': ''.join(json.dumps(r, sort_keys=True) + '\n' for r in unresolved),
            'coverage-accounting.json': json.dumps(coverage, indent=2, sort_keys=True) + '\n',
            'validation.json': json.dumps(report, indent=2, sort_keys=True) + '\n'}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--check', action='store_true')
    args = parser.parse_args()
    outputs = generate()
    for name, content in outputs.items():
        if args.check:
            assert (HERE / name).read_bytes() == content.encode(), name
        else:
            (HERE / name).write_bytes(content.encode())
    print(outputs['validation.json'])


if __name__ == '__main__':
    main()
