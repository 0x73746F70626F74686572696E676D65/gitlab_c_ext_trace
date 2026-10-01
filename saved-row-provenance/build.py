#!/usr/bin/env python3
"""Copy recorded source references and manifest hashes; perform no code analysis."""
import argparse
import collections
import csv
import gzip
import hashlib
import io
import json
from pathlib import Path
import tempfile

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent
FILTER = 'gem_receiver_identifier_filter/filtered_matches.csv'
STOPS = 'depth_limited_name_match/unresolved_stops.jsonl.gz'
SOURCES = {FILTER: 'gem_receiver_identifier_filter/source_files_read.jsonl',
           STOPS: 'depth_limited_name_match/files_read.jsonl'}
FIELDS = ['catalog_file', 'catalog_record', 'catalog_record_sha256', 'catalog_sha256',
          'argument_catalog_file', 'argument_catalog_record', 'argument_catalog_sha256',
          'argument_catalog_reference_status',
          'file', 'line', 'recorded_source_sha256', 'source_catalog', 'source_catalog_sha256',
          'recorded_source_revision', 'provenance_status', 'source_verification', 'unresolved_reason']


def digest(path):
    with path.open('rb') as handle:
        return hashlib.file_digest(handle, 'sha256').hexdigest()


def load_manifest(path):
    result = {}
    for raw in path.read_text().splitlines():
        row = json.loads(raw)
        assert row['file'] not in result or result[row['file']] == row['sha256']
        assert len(row['sha256']) == 64 and all(c in '0123456789abcdef' for c in row['sha256'])
        result[row['file']] = row['sha256']
    return result


def reference(row, number, row_hash, catalog, metadata, manifest):
    file = row.get('file') or ''
    line = row.get('line')
    valid_line = isinstance(line, (int, str)) and str(line).isdigit() and int(line) > 0
    source_hash = manifest.get(file, '')
    gaps = []
    if not file:
        gaps.append('source_file_not_recorded')
    if not valid_line:
        gaps.append('positive_source_line_not_recorded')
    if not source_hash:
        gaps.append('source_hash_not_in_recorded_manifest')
    return dict(catalog_file=catalog, catalog_record=number, catalog_record_sha256=row_hash,
                catalog_sha256=metadata['catalog_sha256'],
                argument_catalog_file=metadata.get('argument_catalog_file', ''),
                argument_catalog_record=row.get('argument_table_line', ''),
                argument_catalog_sha256=metadata.get('argument_catalog_sha256', ''),
                argument_catalog_reference_status=('copied_reference_artifact_digest_verified_no_binding_review'
                                                   if metadata.get('argument_catalog_sha256') else 'not_recorded'),
                file=file,
                line=int(line) if valid_line else '', recorded_source_sha256=source_hash,
                source_catalog=SOURCES[catalog], source_catalog_sha256=metadata['source_catalog_sha256'],
                recorded_source_revision=metadata['revision'],
                provenance_status='unresolved' if gaps else 'recorded_reference_and_manifest_hash',
                source_verification='manifest_only_source_checkout_unavailable',
                unresolved_reason=';'.join(gaps))


def generate(destination, root=ROOT):
    counts, inputs = {}, {}
    for catalog, source_manifest in SOURCES.items():
        directory = (root / catalog).parent
        expected = {name: hash_ for hash_, name in
                    (line.split('  ', 1) for line in (directory / 'SHA256SUMS').read_text().splitlines())}
        for name in (catalog, source_manifest, str(Path(catalog).parent / 'summary.json')):
            inputs[name] = digest(root / name)
            assert inputs[name] == expected[Path(name).name], name
        summary = json.loads((directory / 'summary.json').read_text())
        metadata = dict(catalog_sha256=inputs[catalog], source_catalog_sha256=inputs[source_manifest],
                        revision=summary['gitlab_sha'])
        if catalog == FILTER:
            argument_input = next(item for item in summary['inputs']
                                  if item['repository_path'] == 'static-catalog/entry-argument-sites.csv')
            argument_file = argument_input['repository_path']
            inputs[argument_file] = digest(root / argument_file)
            assert inputs[argument_file] == argument_input['sha256']
            metadata.update(argument_catalog_file=argument_file,
                            argument_catalog_sha256=inputs[argument_file])
        manifest = load_manifest(root / source_manifest)
        anonymous = catalog == FILTER
        output = destination / ('anonymous-filtered.csv.gz' if anonymous else 'unresolved-stops.csv.gz')
        counter = collections.Counter()
        with output.open('wb') as binary, gzip.GzipFile(filename='', mode='wb', fileobj=binary, mtime=0) as packed:
            with io.TextIOWrapper(packed, encoding='utf-8', newline='') as text:
                writer = csv.DictWriter(text, fieldnames=FIELDS, lineterminator='\n')
                writer.writeheader()
                if anonymous:
                    with (root / catalog).open(newline='') as handle:
                        iterator = ((number, row, hashlib.sha256(json.dumps(row, sort_keys=True,
                                     separators=(',', ':')).encode()).hexdigest())
                                    for number, row in enumerate(csv.DictReader(handle), 2)
                                    if row['auth'] in {'unauthenticated', 'conditional_anonymous'})
                        for number, row, row_hash in iterator:
                            result = reference(row, number, row_hash, catalog, metadata, manifest)
                            writer.writerow(result)
                            counter[result['provenance_status']] += 1
                else:
                    with gzip.open(root / catalog, 'rb') as handle:
                        for number, raw in enumerate(handle, 1):
                            row = json.loads(raw)
                            row_hash = hashlib.sha256(raw.rstrip(b'\r\n')).hexdigest()
                            result = reference(row, number, row_hash, catalog, metadata, manifest)
                            writer.writerow(result)
                            counter[result['provenance_status']] += 1
        expected_rows = summary['anonymous_kept'] if anonymous else summary['unresolved_stops_total']
        assert sum(counter.values()) == expected_rows
        counts[output.name] = dict(rows=sum(counter.values()), statuses=dict(counter),
                                   sha256=digest(output))
    result = dict(status='passed_artifact_and_recorded_manifest_checks', outputs=counts,
                  input_sha256=inputs, source_bytes_reverified=False,
                  source_line_ranges_reverified=False, target_code_executed=False,
                  new_call_paths_or_native_source_links=False)
    (destination / 'validation.json').write_text(json.dumps(result, sort_keys=True, indent=2) + '\n')
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--check', action='store_true')
    args = parser.parse_args()
    if args.check:
        with tempfile.TemporaryDirectory(prefix='saved-row-provenance-') as temp:
            directory = Path(temp)
            result = generate(directory)
            for file in directory.iterdir():
                assert digest(file) == digest(HERE / file.name), file.name
    else:
        result = generate(HERE)
    print(json.dumps(result, sort_keys=True, indent=2))


if __name__ == '__main__':
    main()
