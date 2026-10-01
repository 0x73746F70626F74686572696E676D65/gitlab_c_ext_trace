#!/usr/bin/env python3
"""Verify pinned source bytes and recorded line ranges; never parse source code."""
import argparse
import collections
import csv
import gzip
import hashlib
import json
from pathlib import Path
import subprocess

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent
REVISION = '9cfc39017e700a28649858f6a902117f9d5e8edd'
OFFICIAL = 'https://gitlab.com/gitlab-org/gitlab.git'
INPUTS = ['gem_receiver_identifier_filter/filtered_matches.csv',
          'gem_receiver_identifier_filter/source_files_read.jsonl',
          'depth_limited_name_match/unresolved_stops.jsonl.gz',
          'depth_limited_name_match/files_read.jsonl']


def sha(data):
    return hashlib.sha256(data).hexdigest()


def check_source(data, expected, maximum_line):
    if data is None:
        return '', '', 'unresolved_source_file_missing'
    actual, lines = sha(data), len(data.splitlines())
    if actual != expected:
        return actual, lines, 'unresolved_source_digest_mismatch'
    if not isinstance(maximum_line, int) or not 0 < maximum_line <= lines:
        return actual, lines, 'unresolved_recorded_line_out_of_range'
    return actual, lines, 'source_bytes_and_line_range_verified'


def generate(source):
    def git(*args):
        return subprocess.check_output(['git', '-C', str(source), *args], text=True).strip()
    assert git('rev-parse', 'HEAD') == REVISION
    assert git('remote', 'get-url', 'origin') == OFFICIAL
    assert not git('status', '--porcelain=v1', '--untracked-files=no'), 'Modified tracked source files'
    prior = json.loads((HERE / 'validation.json').read_text())
    input_hashes = {}
    manifests = {}
    for name in INPUTS:
        data = (ROOT / name).read_bytes()
        input_hashes[name] = sha(data)
        assert input_hashes[name] == prior['input_sha256'][name], name
        if name.endswith('jsonl'):
            for raw in data.splitlines():
                row = json.loads(raw)
                assert row['file'] not in manifests or manifests[row['file']] == row['sha256']
                manifests[row['file']] = row['sha256']
    refs = {}
    def add(row):
        file, line = row['file'], int(row['line'])
        path = Path(file)
        assert not path.is_absolute() and '..' not in path.parts and line > 0
        count, maximum = refs.get(file, (0, 0))
        refs[file] = (count + 1, max(maximum, line))
    with (ROOT / INPUTS[0]).open(newline='') as handle:
        for row in csv.DictReader(handle):
            if row['auth'] in {'unauthenticated', 'conditional_anonymous'}:
                add(row)
    with gzip.open(ROOT / INPUTS[2], 'rt') as handle:
        for raw in handle:
            add(json.loads(raw))
    records = []
    for file, (count, maximum) in sorted(refs.items()):
        path = source / file
        assert not path.is_symlink(), file
        expected = manifests[file]
        actual, lines, status = check_source(path.read_bytes() if path.is_file() else None, expected, maximum)
        records.append(dict(file=file, recorded_source_sha256=expected, actual_source_sha256=actual,
                            source_line_count=lines, maximum_recorded_line=maximum,
                            recorded_reference_count=count, status=status))
    text = ''.join(json.dumps(row, sort_keys=True) + '\n' for row in records)
    receipt = dict(source_repository=OFFICIAL, revision=REVISION,
                   source_acquisition='exact_commit_fetch_and_sparse_checkout_of_recorded_files',
                   input_sha256=input_hashes, files=len(records),
                   recorded_references=sum(row['recorded_reference_count'] for row in records),
                   status_counts=dict(collections.Counter(row['status'] for row in records)),
                   file_report_sha256=sha(text.encode()), git_worktree_clean=True,
                   source_code_parsed=False, source_semantics_reviewed=False, target_code_executed=False)
    return {'ruby-source-files.jsonl': text,
            'ruby-source-verification.json': json.dumps(receipt, indent=2, sort_keys=True) + '\n'}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--source', type=Path, required=True)
    parser.add_argument('--check', action='store_true')
    args = parser.parse_args()
    outputs = generate(args.source)
    for name, text in outputs.items():
        if args.check:
            assert (HERE / name).read_bytes() == text.encode(), name
        else:
            (HERE / name).write_bytes(text.encode())
    print(outputs['ruby-source-verification.json'])


if __name__ == '__main__':
    main()
