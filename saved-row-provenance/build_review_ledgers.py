#!/usr/bin/env python3
"""Resolve saved evidence pointers only; verify bytes, never analyze native code."""
import argparse
import collections
import csv
import hashlib
import io
import json
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent
CONFIG = [
    ('static-catalog/review-metadata/unresolved-rows.jsonl',
     'static-catalog/entry-argument-sites.jsonl', 'inventory_line', 'inventory_row_sha256', 'site_file', 'site_line'),
    ('static-catalog/registration-provenance/unresolved-rows.jsonl',
     'static-catalog/argument-inventory-roots.jsonl', 'root_evidence', 'root_row_sha256', 'registration_file', 'registration_line'),
]


def digest(blob):
    return hashlib.sha256(blob).hexdigest()


def resolve_record(gap, raw_rows, pointer, hash_key):
    reference = gap[pointer]
    number = int(reference.rsplit(':', 1)[1]) if isinstance(reference, str) else reference
    assert isinstance(number, int) and 0 < number <= len(raw_rows)
    raw = raw_rows[number - 1]
    assert digest(raw) == gap[hash_key], ('original record digest mismatch', number)
    row = json.loads(raw)
    if 'entry_id' in gap:
        assert gap['entry_id'] == row['entry_id']
    return number, row


def generate(root=ROOT):
    inputs = {}
    def read(name):
        blob = (root / name).read_bytes()
        inputs[name] = digest(blob)
        return blob
    files_blob = read('static-catalog/files-scanned.csv')
    files = {(r['gem'], r['file']): r for r in csv.DictReader(io.StringIO(files_blob.decode()))}
    manifest = {(r['gem'], r['locked_version']): r for r in json.loads(read('static-catalog/fetch-manifest.json'))}
    expected = {f'static-catalog/{name}': hash_ for hash_, name in
                (line.split('  ', 1) for line in (root / 'static-catalog/SHA256SUMS').read_text().splitlines())}
    cache, rows = {}, []
    for ledger, catalog, pointer, hash_key, file_key, line_key in CONFIG:
        ledger_blob, catalog_blob = read(ledger), read(catalog)
        raw_rows = catalog_blob.splitlines()
        for ledger_number, raw_gap in enumerate(ledger_blob.splitlines(), 1):
            gap = json.loads(raw_gap)
            number, original = resolve_record(gap, raw_rows, pointer, hash_key)
            file, line = original.get(file_key, ''), original.get(line_key, '')
            line = int(line) if str(line).isdigit() and int(line) > 0 else ''
            record = files.get((original['gem'], file))
            source_hash = record['sha256'] if record else ''
            status = 'unresolved_missing_source_manifest_record'
            line_hash = ''
            if record:
                package = manifest.get((original['gem'], record['source_variants'].split(';')[0]))
                path = Path(package['source_directory']) / file if package else None
                if path and path.is_file():
                    if path not in cache:
                        data = path.read_bytes()
                        assert digest(data) == source_hash, str(path)
                        cache[path] = data.splitlines()
                    if line and line <= len(cache[path]):
                        line_hash = digest(cache[path][line - 1])
                        status = 'source_bytes_and_line_range_verified'
                    else:
                        status = 'unresolved_source_line_missing_or_out_of_range'
                else:
                    status = 'recorded_manifest_only_source_bytes_unavailable'
            rows.append(dict(ledger_file=ledger, ledger_record=ledger_number,
                             ledger_sha256=digest(ledger_blob), ledger_record_sha256=digest(raw_gap),
                             catalog_file=catalog, catalog_record=number, catalog_sha256=digest(catalog_blob),
                             catalog_record_sha256=gap[hash_key], file=file, line=line,
                             source_catalog='static-catalog/files-scanned.csv',
                             source_catalog_sha256=inputs['static-catalog/files-scanned.csv'],
                             recorded_source_sha256=source_hash, verified_source_line_sha256=line_hash,
                             provenance_status=status, original_gap_status=gap['status'],
                             semantic_gaps='unchanged_not_reassessed'))
    for name, hash_ in inputs.items():
        assert expected[name] == hash_, name
    output = io.StringIO(newline='')
    writer = csv.DictWriter(output, fieldnames=list(rows[0]), lineterminator='\n')
    writer.writeheader()
    writer.writerows(rows)
    report = dict(status='passed', rows=len(rows), verified_source_files=len(cache),
                  rows_by_ledger=dict(collections.Counter(r['ledger_file'] for r in rows)),
                  provenance_statuses=dict(collections.Counter(r['provenance_status'] for r in rows)),
                  input_sha256=inputs, new_bindings_or_paths=False, target_code_executed=False,
                  semantic_gaps_reassessed=False)
    return {'review-ledgers.csv': output.getvalue(),
            'review-ledgers-validation.json': json.dumps(report, sort_keys=True, indent=2) + '\n'}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--check', action='store_true')
    args = parser.parse_args()
    outputs = generate()
    for name, text in outputs.items():
        if args.check:
            assert (HERE / name).read_bytes() == text.encode(), name
        else:
            (HERE / name).write_bytes(text.encode())
    print(outputs['review-ledgers-validation.json'])


if __name__ == '__main__':
    main()
