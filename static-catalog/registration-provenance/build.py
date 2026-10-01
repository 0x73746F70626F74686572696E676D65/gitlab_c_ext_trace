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
          'fetch-manifest.json', 'review-metadata/source-validation.json')


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
    for name in INPUTS[:-1]:
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
                  binding_semantics_revalidated=False)
    return {'rows.jsonl': ''.join(json.dumps(r, sort_keys=True) + '\n' for r in rows),
            'rows.csv': output.getvalue(),
            'unresolved-rows.jsonl': ''.join(json.dumps(r, sort_keys=True) + '\n' for r in unresolved),
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
