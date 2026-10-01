#!/usr/bin/env python3
"""Validate source references and render the catalog's delivery notes."""
import csv, hashlib, json, pathlib, unittest
from entry_catalog import select_source_files

def read_csv(path):
    with path.open(newline='') as f:
        return list(csv.DictReader(f))

def main():
    out=pathlib.Path(__file__).resolve().parents[1]
    summary=json.loads((out/'summary.json').read_text())
    sources={(r['gem'],r['file']):r for r in select_source_files(out)}
    for record in sources.values():
        assert hashlib.sha256(pathlib.Path(record['absolute_path']).read_bytes()).hexdigest()==record['sha256']
    lines={}
    def source_lines(gem,path):
        key=(gem,path)
        if key not in lines:
            record=sources[key]
            data=pathlib.Path(record['absolute_path']).read_bytes()
            assert hashlib.sha256(data).hexdigest()==record['sha256']
            lines[key]=data.decode('utf-8',errors='replace').splitlines()
        return lines[key]
    entries=read_csv(out/'entry-points.csv')
    sites=read_csv(out/'sites.csv')
    rows=read_csv(out/'entry-argument-sites.csv')
    unresolved=read_csv(out/'unresolved-hops.csv')
    assert len(entries)==summary['entry_points']
    assert len(sites)==summary['sites']
    assert len(rows)==summary['kept_rows']
    assert len(unresolved)==summary['unresolved_hops']
    assert len({r['entry_id'] for r in entries})==len(entries)
    for entry in entries:
        line=int(entry['registration_line'])
        assert entry['registration'] in source_lines(entry['gem'],entry['registration_file'])[line-1]
    for site in sites:
        assert 0<int(site['line'])<=len(source_lines(site['gem'],site['file']))
        record=sources[(site['gem'],site['file'])]
        data=pathlib.Path(record['absolute_path']).read_bytes()
        assert data.count(b'\n',0,int(site['byte']))+1==int(site['line'])
    for hop in unresolved:
        assert 0<int(hop['line'])<=len(source_lines(hop['gem'],hop['file']))
    key=lambda r:(r['entry_id'],r['argument_index'],r['site_file'],r['site_line'],r['callee_or_store'],r['slot'],r['argument_slot'])
    assert len({key(r) for r in rows})==len(rows)
    with (out/'entry-argument-sites.jsonl').open() as f:
        assert [json.loads(line) for line in f]==[{k:(int(v) if k in {'arity','argument_index','site_line','registration_line'} else v) for k,v in r.items()} for r in rows]
    suite=unittest.defaultTestLoader.discover(str(out/'scripts'),pattern='test_*.py')
    result=unittest.TextTestRunner(verbosity=1).run(suite)
    assert result.wasSuccessful()
    manifest=json.loads((out/'fetch-manifest.json').read_text())
    assert len(read_csv(out/'locked-gems.csv'))==summary['locked_package_entries']
    assert all(r['status']=='fetched' for r in manifest)
    assert all(r['checksum_status']=='matches_lock' for r in manifest if r['source_type']=='GEM')
    validation=dict(status='passed',parser_transfer_tests=result.testsRun,
        registration_source_references_checked=len(entries),site_source_references_checked=len(sites),
        unresolved_source_references_checked=len(unresolved),kept_rows_checked=len(rows),
        source_digests_verified=len(sources),rubygems_packages_matching_lock_sha256=sum(r['source_type']=='GEM' for r in manifest),
        extension_or_application_code_executed=False)
    (out/'validation.json').write_text(json.dumps(validation,indent=2)+'\n')
    report=[
        'Ruby-callable C-extension argument-provenance catalog',
        f'GitLab default branch: {summary["default_branch"]}',
        f'GitLab SHA: {summary["gitlab_sha"]}',
        f'Gemfile.lock SHA256: {summary["lock_sha256"]}',
        f'Locked gems: {summary["locked_gem_names"]} names; {summary["locked_package_entries"]} version/platform entries',
        f'Fetched locked entries: {summary["fetched_locked_entries"]}; fetch failures: {len(summary["gems_not_fetched"])}',
        f'C-extension gems scanned: {summary["extensions_scanned"]}; native build roots: {summary["extension_build_roots"]}',
        f'Distinct native source files scanned: {summary["files_scanned"]}',
        f'Ruby registrations: {summary["entry_points"]}; resolved bindings/signatures: {summary["resolved_entry_points"]}',
        f'Resolved roots with Ruby-passed arguments: {summary["entry_points_with_ruby_arguments"]}',
        f'Selected sites with parsed enclosing functions: {summary["sites"]}',
        f'Kept entry/site pairs: {summary["kept_pairs"]}; argument/slot rows: {summary["kept_rows"]}',
        f'Unresolved argument-provenance hops: {summary["unresolved_hops"]}',
        f'Dropped local-length rewrites: {summary["dropped_argument_transfers"]}',
        f'Parser diagnostic records: {summary["parser_diagnostics"]} in {summary["files_with_parser_diagnostics"]} files',
        f'Unparsed lexical candidates: {summary["lexical_candidates_unparsed"]}; skipped files/archives: {summary["skipped_files"]}',
        '',
        'No pairs passed the conservative unchanged-argument rule. This is not a finding that all paths are bound.',
        'Unresolved macros, external calls, indirect operations, callback bindings, and parser recovery block paths.',
        'See unresolved-hops.csv, index-issues.csv, parser-diagnostics.csv, and files-skipped.csv for coverage limits.',
        '',
        'Unresolved reasons (argument-specific records):',
        *[f'  {reason}: {count}' for reason,count in sorted(summary['unresolved_hops_by_reason'].items())],
        '',
        'Scanned C-extension gems:',
        '  '+', '.join(summary['gems_with_extensions']),
        '',
        f'Validation passed: {result.testsRun} inert-snippet parser/transfer tests and all exported source references.',
        'GitLab, Ruby wrappers, gem extension binaries, build scripts, and application code were not executed.',
    ]
    (out/'summary.txt').write_text('\n'.join(report)+'\n')
    print(json.dumps(validation,indent=2))

if __name__=='__main__':
    main()
